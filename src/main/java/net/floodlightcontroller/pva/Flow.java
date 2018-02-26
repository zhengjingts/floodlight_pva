package net.floodlightcontroller.pva;

import org.projectfloodlight.openflow.types.IPv4Address;

public class Flow {
	protected IPv4Address srcIP;
	protected IPv4Address dstIP;
	protected int protocol;
	protected int srcPort;
	protected int dstPort;
	
	public Flow(IPv4Address srcIP, IPv4Address dstIP, int protocol, int srcPort, int dstPort) {
		this.srcIP    = srcIP;
		this.dstIP    = dstIP;
		this.protocol = protocol;
		this.srcPort  = srcPort;
		this.dstPort  = dstPort;
	}
	
	public IPv4Address getSrcIP() {
		return srcIP;
	}
	
	public IPv4Address getDstIP() {
		return dstIP;
	}
	
	public int getProtocol() {
		return protocol;
	}
	
	public int getSrcPort() {
		return srcPort;
	}
	
	public int getDstPort() {
		return dstPort;
	}
	
	@Override
	public String toString() {
		return String.format("<%s, %s, %d, %d, %d>", srcIP.toString(), dstIP.toString(), protocol, srcPort, dstPort);
	}
	
    @Override
    public int hashCode() {
        int hproto = (protocol << 8) | (protocol & 0x000000FF);
        int hport = ((srcPort ^ hproto) << 16) | ((dstPort ^ hproto) & 0x0000FFFF);
        
        return (int) (srcIP.getInt() ^ dstIP.getInt() ^ hport);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        
        Flow flow = (Flow) obj;
        if (flow.getSrcIP().equals(srcIP) && flow.getDstIP().equals(dstIP) && (flow.getProtocol() == protocol)
        		&& (flow.getSrcPort() == srcPort) && (flow.getDstPort() == dstPort))
    		return true;
    	return false;
    }
}
