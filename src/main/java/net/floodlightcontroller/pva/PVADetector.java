package net.floodlightcontroller.pva;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;

public class PVADetector implements IFloodlightModule, IOFMessageListener, IOFSwitchListener, ILinkDiscoveryListener,
										IDetectionChannelEventHandler {
	
	protected IFloodlightProviderService floodlightProviderService;
	protected IOFSwitchService           switchService;
	protected ILinkDiscoveryService      linkDiscoveryService;
	protected Map<DatapathId, Boolean>   authenticSwitches; // True means authentic switch, false means fake switch
	protected Map<DatapathId, Boolean>   edgeSwitches; // True means ingress switch, false means egress switch
	protected ReadWriteLock              switchesLock;
	
	// parameters
//	protected double lambda;
	protected double alpha    = 0.0;
	protected int    tao      = 20;
	protected long   timeout  = 1000;
	protected int    limit    = 10;
	
	protected Map<Flow, DetectionChannel> detectionChannels;
	protected ReadWriteLock               detectionChannelsLock;
	
	protected static Logger logger = LoggerFactory.getLogger(PVADetector.class);

	protected List<Worker> workers;
	
	private static final int    numWorkers    = 5;
	private static final int    detectionTble = 0;
	private static final int    forwardingTbl = 1;
	private static final int    rulePriority  = 100;
	private static final U64    cookie        = U64.parseHex("8796A5B4C3D2E1F0");
	private static final byte[] hmacKey       = "zj@tsinghua.edu.cn".getBytes();
	
	
	@Override
	public void detectionChannelStateChanged(Flow flow, DetectionChannelState original, DetectionChannelState present) {
		
		switch (present) {
		case CHANNEL_CLOSE:
			DetectionChannel detectionChannel;
			detectionChannelsLock.readLock().lock(); {
				detectionChannel = detectionChannels.get(flow);
			} detectionChannelsLock.readLock().unlock();
			
			int omega = detectionChannel.randomOmega();
			detectionChannel.setNextOpenTimeAsync(System.currentTimeMillis() + omega * 1000);
			
			logger.info("Experiment - Event - Close Channel: {}",
					String.format("![%s] Omega = ![%d]", flow.toString(), omega));
			
			addFlowRule(flow, omega, false);
			break;
			
		case CHANNEL_MISMATCH:
		case CHANNEL_TIMEOUT:
			detectionChannelsLock.readLock().lock(); {
				detectionChannel = detectionChannels.get(flow);
			} detectionChannelsLock.readLock().unlock();
			
			omega = 0;
			
			logger.info("Experiment - Event - Remove Flow: {}",
					String.format("![%s] Omega = ![%d]", flow.toString(), omega));
			
			addFlowRule(flow, omega, false);
			break;
			
		case CHANNEL_ESTABLISH:
		case CHANNEL_OPEN:
		case CHANNEL_FINAL:
		default:
			break;
		}
	}
	
	protected class Task {
		private Flow       flow;
		private DatapathId dpid;
		private Ethernet    eth;
		
		public Task(Flow flow, DatapathId dpid, Ethernet eth) {
			this.flow = flow;
			this.dpid = dpid;
			this.eth  = eth;
		}
		
		public Flow getFlow() {
			return flow;
		}
		
		public DatapathId getDPID() {
			return dpid;
		}
		
		public Ethernet getEth() {
			return eth;
		}
	}
	
	protected class Worker extends Thread {
		private BlockingQueue<Task> tasks;
		
		public Worker () {
			tasks = new LinkedBlockingQueue<Task>();
		}
		
		public void feed(Flow flow, DatapathId dpid, Ethernet eth) {
			try {
				tasks.put(new Task(flow, dpid, eth));
			} catch (InterruptedException e) {
				logger.error("Error - Worker - Feed Task:", e);
			}
		}
		
		@Override
		public void run() {
			Task task;
			while(true) {
				try {
					task = tasks.take();
				} catch (InterruptedException e) {
					logger.error("Error - Worker - Retrieve Task:", e);
					continue;
				}
				
				Flow flow = task.getFlow();
//				logger.info("Debug - Flow: {}", String.format(
//						"%s %s %d %d %d", flow.getSrcIP().toString(), flow.getDstIP().toString(), flow.getProtocol(),
//						flow.getSrcPort(), flow.getDstPort()));
				Ethernet eth = task.getEth();
				
				DetectionChannel detectionChannel;
				detectionChannelsLock.readLock().lock(); {
					detectionChannel = detectionChannels.get(flow);
				} detectionChannelsLock.readLock().unlock();
				
				if (detectionChannel == null) {
					detectionChannel = new DetectionChannel(flow, alpha, tao, timeout, limit);
					
					detectionChannelsLock.writeLock().lock(); {
						detectionChannels.put(flow, detectionChannel);
					} detectionChannelsLock.writeLock().unlock();
					
					int omega = detectionChannel.randomOmega();
					detectionChannel.setNextOpenTimeAsync(System.currentTimeMillis() + omega * 1000);
					
					logger.info("Experiment - Event - Initialize Channel: {}",
							String.format("![%s] Omega = ![%d]", flow.toString(), omega));
					
					addFlowRule(flow, omega, true);
					
				} else {
					DatapathId dpid = task.getDPID();
//					logger.info("Debug - Worker - Recieved Packet: {}",
//							String.format("![%s] ![%s]", dpid.toString(), flow.toString()));
					try {
						switchesLock.readLock().lock();
						if (edgeSwitches.containsKey(dpid)) {
							try {
								byte[] hmac = HMacMD5.getHmacMd5Bytes(hmacKey, eth.serialize());
								if (edgeSwitches.get(dpid)) {
									logger.info("Debug - Worker - Packet Enter: {}",
											String.format("![%s] ![%d]", flow.toString(), hmac.hashCode()));
									detectionChannel.enter(hmac);
									composePacketOut(dpid, eth, 2);
								} else {
									logger.info("Debug - Worker - Packet Leave: {}",
											String.format("![%s] ![%d]", flow.toString(), hmac.hashCode()));
									detectionChannel.leave(hmac);
									composePacketOut(dpid, eth, 1);
								}
							} catch (NoSuchAlgorithmException e) {
								logger.error("Error - Recieve - HMAC", e);
							}
						}
					} finally {
						switchesLock.readLock().unlock();
					}
				}
			}
		}
	}
	
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
			FloodlightContext cntx) {
		if (msg.getType() == OFType.PACKET_IN) {
//			OFPacketIn pktin = (OFPacketIn)msg;
			
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			if (eth.getEtherType() == EthType.IPv4) {
				IPv4 ip = (IPv4) eth.getPayload();
				
				Flow flow = null;
				if (ip.getProtocol() == IpProtocol.TCP) {
					TCP tcp = (TCP)ip.getPayload();
					flow = new Flow(ip.getSourceAddress(), ip.getDestinationAddress(),
							(int)(IpProtocol.TCP.getIpProtocolNumber()),
							tcp.getSourcePort().getPort(), tcp.getDestinationPort().getPort());
					// A hacking way to fix checksum.
					tcp.setChecksum((short)0);
				} else if (ip.getProtocol() == IpProtocol.UDP) {
					UDP udp = (UDP)ip.getPayload();
					flow = new Flow(ip.getSourceAddress(), ip.getDestinationAddress(),
							(int)(IpProtocol.UDP.getIpProtocolNumber()),
							udp.getSourcePort().getPort(), udp.getDestinationPort().getPort());
					// A hacking way to fix checksum.
					udp.setChecksum((short)0);
//					logger.info("Debug - Worker - UDP Packet: {}", Arrays.toString(udp.serialize()));
				}
				
				if (flow != null) {
					logger.info("Debug - Worker - Packet-In Message Recieved: {}",
							String.format("![%s] Dpid = ![%s], Worker = ![%d]",
									flow.toString(), sw.getId().toString(), Math.abs(flow.hashCode() % numWorkers)));
//					logger.info("Debug - Worker - Ethernet Packet: {}", Arrays.toString(eth.serialize()));
					
					workers.get(Math.abs(flow.hashCode() % numWorkers)).feed(flow, sw.getId(), eth);
				}
			}
		}
		
		return Command.CONTINUE;
	}
	
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) {
		for (LDUpdate update : updateList) {
			switch (update.getOperation()) {
			case PORT_UP:
				break;
				
			case LINK_UPDATED:
				
				if (update.getType() != LinkType.DIRECT_LINK)
					break;
				
				try {
					switchesLock.readLock().lock();
					if (authenticSwitches.containsKey(update.getDst()))
						break;
				} finally {
					switchesLock.readLock().unlock();
				}
				
				// A hack way to determine the topology. We setup the topology as follows.
				// We always use corresponding ports to link to a certain switch,
				// Port 3 to fake switch, 4 to ingress switch, 5 to egress switch, and 2 to the left switch.
				try {
					switchesLock.writeLock().lock();
					switch (update.getSrcPort().getPortNumber()) {
					case 2:
						authenticSwitches.put(update.getDst(), true);
						logger.info("Debug - Link - Link Update: {}",
								String.format("![%s] State = ![Authentic]", update.getDst()));
						break;
					case 3:
						authenticSwitches.put(update.getDst(), false);
						logger.info("Debug - Link - Link Update: {}",
								String.format("![%s] State = ![Fake]", update.getDst()));
						break;
					case 4:
						authenticSwitches.put(update.getDst(), true);
						logger.info("Debug - Link - Link Update: {}",
								String.format("![%s] State = ![Ingress]", update.getDst()));
						edgeSwitches.put(update.getDst(), true);
						break;
					case 5:
						authenticSwitches.put(update.getDst(), true);
						logger.info("Debug - Link - Link Update: {}",
								String.format("![%s] State = ![Egress]", update.getDst()));
						edgeSwitches.put(update.getDst(), false);
						break;
					default:
						break;
					}
				} finally {
					switchesLock.writeLock().unlock();
				}
				
				try {
					switchesLock.readLock().lock();
					if (authenticSwitches.containsKey(update.getSrc()))
						break;
				} finally {
					switchesLock.readLock().unlock();
				}
				
				try {
					switchesLock.writeLock().lock();
					switch (update.getDstPort().getPortNumber()) {
					case 2:
						authenticSwitches.put(update.getSrc(), true);
						
						logger.info("Debug - Link - Link Update: {}",
								String.format("![%s] State = ![Authentic]", update.getSrc()));
						
						break;
						
					case 3:
						authenticSwitches.put(update.getSrc(), false);
						
						logger.info("Debug - Link - Link Update: {}",
								String.format("![%s] State = ![Fake]", update.getSrc()));
						
						break;
						
					case 4:
						authenticSwitches.put(update.getSrc(), true);
						
						logger.info("Debug - Link - Link Update: {}",
								String.format("![%s] State = ![Ingress]", update.getSrc()));
						
						edgeSwitches.put(update.getSrc(), true);
						break;
						
					case 5:
						authenticSwitches.put(update.getSrc(), true);
						
						logger.info("Debug - Link - Link Update: {}",
								String.format("![%s] State = ![Egress]", update.getSrc()));
						
						edgeSwitches.put(update.getSrc(), false);
						break;
						
					default:
						break;
					}
				} finally {
					switchesLock.writeLock().unlock();
				}
				
				break;

			default: 
				break;
			}
		}
	}
	
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		switchService             = context.getServiceImpl(IOFSwitchService.class);
		linkDiscoveryService      = context.getServiceImpl(ILinkDiscoveryService.class);
		authenticSwitches         = new HashMap<DatapathId, Boolean>();
		edgeSwitches              = new HashMap<DatapathId, Boolean>();
		
		switchesLock              = new ReentrantReadWriteLock();
		
		detectionChannels    = new HashMap<Flow, DetectionChannel>();
		
		workers               = new ArrayList<Worker>();
		detectionChannelsLock = new ReentrantReadWriteLock();
		for (int i = 0; i < numWorkers; i ++)
			workers.add(new Worker());
		
		setConfig(context.getConfigParams(this));		
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// Add event listeners
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
		switchService.addOFSwitchListener(this);
		linkDiscoveryService.addListener(this);
		
		DetectionChannel.registerEventHandler(this);
		
		for (int i = 0; i < numWorkers; i ++)
			workers.get(i).start();
	}
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IOFSwitchService.class);
		l.add(ILinkDiscoveryService.class);
		return l;
	}

	@Override
	public String getName() {
		return PVADetector.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}
	
	private void addFlowRule(Flow flow, int omega, boolean initial) {
		try {
			switchesLock.readLock().lock();
			for (DatapathId dpid : authenticSwitches.keySet()) {
				if (authenticSwitches.get(dpid)) {
					IOFSwitch sw       = null;
					OFFlowAdd flowRule = null;
					
					if (edgeSwitches.containsKey(dpid)) {
						sw = switchService.getSwitch(dpid);
						
						Match match = sw.getOFFactory().buildMatch()
								.setExact(MatchField.ETH_TYPE, EthType.IPv4)
								.setMasked(MatchField.IPV4_SRC, flow.getSrcIP(), IPv4Address.ofCidrMaskLength(32))
								.setMasked(MatchField.IPV4_DST, flow.getDstIP(), IPv4Address.ofCidrMaskLength(32))
								.build();
						
						OFInstruction gotoForwardingTbl = sw.getOFFactory().instructions()
								.gotoTable(TableId.of(forwardingTbl));
						List<OFInstruction> instructions = new ArrayList<OFInstruction>();
						instructions.add(gotoForwardingTbl);
						
						flowRule = sw.getOFFactory().buildFlowAdd()
								.setCookie(cookie)
								.setPriority(rulePriority)
								.setTableId(TableId.of(detectionTble))
								.setMatch(match)
								.setInstructions(instructions)
								.setHardTimeout(omega)
								.build();
						
	
					} else if (initial) {
						sw = switchService.getSwitch(dpid);
						
						Match match = sw.getOFFactory().buildMatch()
								.setExact(MatchField.ETH_TYPE, EthType.IPv4)
								.setMasked(MatchField.IPV4_SRC, flow.getSrcIP(), IPv4Address.ofCidrMaskLength(32))
								.setMasked(MatchField.IPV4_DST, flow.getDstIP(), IPv4Address.ofCidrMaskLength(32))
								.build();
						
						OFInstruction gotoForwardingTbl = sw.getOFFactory().instructions()
								.gotoTable(TableId.of(forwardingTbl));
						List<OFInstruction> instructions = new ArrayList<OFInstruction>();
						instructions.add(gotoForwardingTbl);
						
						flowRule = sw.getOFFactory().buildFlowAdd()
								.setCookie(cookie)
								.setPriority(rulePriority)
								.setTableId(TableId.of(detectionTble))
								.setMatch(match)
								.setInstructions(instructions)
								.build();
					}
					
					if (sw != null) {
						logger.debug("Debug - Switch - Add Flow Rules: {}",
								String.format("![%s] ![%d] ![%b]", dpid.toString(), omega, initial));
						
						sw.write(flowRule);
					}
				}
			}
		} finally {
			switchesLock.readLock().unlock();
		}
	}
	
	private void composePacketOut(DatapathId dpid, Ethernet eth, int port){
		IOFSwitch sw = switchService.getActiveSwitch(dpid);
		OFPacketOut packetOut = sw.getOFFactory().buildPacketOut()
				.setData(eth.serialize())
			    .setActions(Collections.singletonList(
			    		(OFAction) sw.getOFFactory().actions().output(OFPort.of(port), 0xffFFffFF)))
			    .setInPort(OFPort.CONTROLLER)
			    .build();
		sw.write(packetOut);
	}
	
	private void initDefaultRules(DatapathId dpid) {
		IOFSwitch sw = switchService.getSwitch(dpid);
				
		// Clear all detection rules.
		OFFlowDelete flowdel = sw.getOFFactory().buildFlowDelete()
				.setTableId(TableId.ALL)
				.setCookie(cookie)
				.setCookieMask(U64.parseHex("FFFFFFFFFFFFFFFF"))
				.build();
		
		logger.debug("Debug - Switch - Initialize Rules: {}",
				String.format("![%s]", dpid.toString()));
		
		sw.write(flowdel);
	}
	
	private void setConfig(Map<String, String> parameters) {
//		String sLambda = parameters.get("lambda");
//        if (!Strings.isNullOrEmpty(sLambda)) {
//            try {
//            	lambda = Double.parseDouble(sLambda);
//            } catch (NumberFormatException e) {
//                logger.error("Error - Setting - Invalid lambda specifier:", e);
//            }
//            
//            logger.info("Experiment - Setting - Lambda: {}", String.format("![%f]", lambda));
//        }
        
        String sAlpha = parameters.get("alpha");
        if (!Strings.isNullOrEmpty(sAlpha)) {
            try {
            	alpha = Double.parseDouble(sAlpha);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid alpha specifier:", e);
            }
            
            logger.info("Experiment - Setting - Alpha: {}", String.format("![%f]", alpha));
        }
        
		String sTao = parameters.get("tao");
        if (!Strings.isNullOrEmpty(sTao)) {
            try {
            	tao = Integer.parseInt(sTao);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid tao specifier:", e);
            }
            
            logger.info("Experiment - Setting - Tao: {}", String.format("![%d]", tao));
        }
        
        String sTimeout = parameters.get("timeout");
        if (!Strings.isNullOrEmpty(sTimeout)) {
            try {
            	timeout = Long.parseLong(sTimeout);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid timeout specifier:", e);
            }
            
            logger.info("Experiment - Setting - Timeout: {}", String.format("![%d]", timeout));
        }
	}

	@Override
	public void switchAdded(DatapathId switchId) {
		logger.info("Experiment - Event - Add Switch: {}",
				String.format("![%s] ![%d]", switchId.toString(), System.currentTimeMillis()));
		
		initDefaultRules(switchId);
	}

	@Override
	public void switchRemoved(DatapathId switchId) {
		
	}

	@Override
	public void switchActivated(DatapathId switchId) {
		
	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {
		
	}

	@Override
	public void switchChanged(DatapathId switchId) {
		
	}

	@Override
	public void switchDeactivated(DatapathId switchId) {
		
	}
}
