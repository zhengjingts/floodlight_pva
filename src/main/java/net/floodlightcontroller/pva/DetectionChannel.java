package net.floodlightcontroller.pva;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DetectionChannel {
	protected Flow         flow;
	
	// HMACs and Timeouts for each packet record
	protected List<byte[]> hmacs;
	protected List<Long>   timeouts;
	protected Lock         hmacsLock;
	
	protected double                currentAlpha;
	protected DetectionChannelState state;
	
	protected long nextOpenTime;
	private   long latestTimeout;
	
//	private List<List<byte[]>>  hmacBuckets;
//	private List<Lock>          hmacBucketsLocks;
	
	// Global varieties
	protected static List<IDetectionChannelEventHandler> eventHandlers;
	protected static ReadWriteLock                       eventHandlersLock;
	protected static TimeoutHandler                      timeoutHandlerThread;
	protected static Logger                              logger;
	static {
		logger = LoggerFactory.getLogger(DetectionChannel.class);
		
		timeoutHandlerThread = new TimeoutHandler();
		timeoutHandlerThread.start();
		
		eventHandlers     = new ArrayList<IDetectionChannelEventHandler>();
		eventHandlersLock = new ReentrantReadWriteLock();
	}
	
	// Local parameters
	protected final double alpha;
	protected final int    tao;
	protected final long   timeout;
//	protected final int    limit;
	
	// Global parameters
	private static final int  bucketSize = 10;
	private static final long bucketSpan = 1000;
	
	public DetectionChannel(Flow flow, double alpha, int tao, long timeout, int limit) {
		this.flow    = flow;
		this.alpha   = alpha;
		this.tao     = tao;
		this.timeout = timeout;
//		this.limit   = limit;
		
		hmacs     = new LinkedList<byte[]>();
		timeouts  = new LinkedList<Long>();
		hmacsLock = new ReentrantLock();
		
		nextOpenTime  = 0;
		latestTimeout = 0;
		
//		hmacBuckets      = new ArrayList<List<byte[]>>();
//		hmacBucketsLocks = new ArrayList<Lock>();
//		for (int i = 0; i < bucketSize; i ++) {
//			hmacBuckets.add(new ArrayList<byte[]>());
//			hmacBucketsLocks.add(new ReentrantLock());
//		}
		
		state = DetectionChannelState.CHANNEL_CLOSE;
	}
	
	public void enter(byte[] hmac) {
		try {
			hmacsLock.lock();
			
			switch (state) {
			case CHANNEL_CLOSE:
				if (System.currentTimeMillis() >= nextOpenTime)
					changeStateAsync(DetectionChannelState.CHANNEL_ESTABLISH);
				else
					return;
			case CHANNEL_OPEN:
//				if (hmacs.size() >= limit) {
//					changeStateAsync(DetectionChannelState.CHANNEL_FINAL);
//					return;
//				}
			case CHANNEL_ESTABLISH:
				break;
			
			case CHANNEL_FINAL:
			case CHANNEL_TIMEOUT:
			case CHANNEL_MISMATCH:
			default:
				return;
			}
			
			long t = System.currentTimeMillis() + timeout;
			
			hmacs.add(hmac);
			timeouts.add(t);
			
			logger.info("Experiment - Record - Record HMAC: {}",
					String.format("HMAC = ![%d], Timeout = ![%d], Size = ![%d]", hmac.hashCode(), t, hmacs.size()));
			
			if ( ((long) (t/bucketSpan)) != ((long) (latestTimeout/bucketSpan)) )
				timeoutHandlerThread.addTimeout(this, t);
			
			latestTimeout = t;
		} finally {
			hmacsLock.unlock();
		}
	}
	
	public void leave(byte[] hmac) {
		try {
			hmacsLock.lock();
			
			switch (state) {
			case CHANNEL_ESTABLISH:
				int pos = findHmacAsync(hmac);
				if (pos >= 0) {
					logger.info("Experiment - Detection - Match: {}", String.format(
							"![%s] ![CHANNEL_ESTABLISH] HMAC = ![%d], Record = ![%d]",
							flow.toString(), hmac.hashCode(), hmacs.get(0).hashCode()));
					for (int i = 0; i <= pos; i ++) {
						hmacs.remove(0);
						timeouts.remove(0);
					}
					
					double lambda = 1 - currentAlpha;
					currentAlpha = currentAlpha + (1-currentAlpha) * 0.001;
					
					logger.info("Debug - Record - Match: {}", String.format(
							"![%s] ![CHANNEL_ESTABLISH] HMAC = ![%d], Pos = ![%d], Lambda = ![%f], Alpha = ![%f], Size = ![%d]",
							flow.toString(), hmac.hashCode(), pos, lambda, currentAlpha, hmacs.size()));

					if (Math.random() < lambda)
						changeStateAsync(DetectionChannelState.CHANNEL_OPEN);
					else {
						if (hmacs.size() == 0)
							changeStateAsync(DetectionChannelState.CHANNEL_CLOSE);
						else
							changeStateAsync(DetectionChannelState.CHANNEL_FINAL);
					}
				} else {
					logger.info("Experiment - Detection - Mismatch: {}",// TODO
							String.format("![%s] ![CHANNEL_ESTABLISH] HMAC = ![%d]", flow.toString(), hmac.hashCode()));
//					logger.info("Debug - Record - Mismatch: {}",
//							String.format("CHANNEL_ESTABLISH Current HMAC=%s", Arrays.toString(hmac)));
//					for (byte[] rhmac : hmacs)
//						logger.info("Debug - Record - Mismatch: {}",
//								String.format("CHANNEL_ESTABLISH Record HMAC=%s", Arrays.toString(rhmac)));
				}
				break;
				
			case CHANNEL_OPEN:
				// TODO: test for mismatch.
				if (Arrays.equals(hmacs.get(0), hmac)) {
//				pos = findHmacAsync(hmac);
//				if (pos >= 0) {
//					// TODO: test for mismatch
//					if (pos > 0) {
//						logger.info("Debug - Record - Out of Order: {}",
//								String.format("CHANNEL_OPEN Current HMAC=%s", Arrays.toString(hmac)));
//						for (byte[] rhmac : hmacs)
//							logger.info("Debug - Record - Out of Order: {}",
//									String.format("CHANNEL_OPEN Record HMAC=%s", Arrays.toString(rhmac)));
//					}
					
					logger.info("Experiment - Detection - Match: {}", String.format(
							"![%s] ![CHANNEL_OPEN] HMAC = ![%d], Record = ![%s]",
							flow.toString(), hmac.hashCode(), hmacs.get(0).toString()));
					
					hmacs.remove(0);
					timeouts.remove(0);
					
					double lambda = 1 - currentAlpha;
					currentAlpha = currentAlpha + (1-currentAlpha) * 0.25;
					
					logger.info("Debug - Record - Match: {}", String.format(
							"![%s] ![CHANNEL_OPEN] HMAC = ![%d], Lambda = ![%f], Alpha = ![%f], Size = ![%d]",
							flow.toString(), hmac.hashCode(), lambda, currentAlpha, hmacs.size()));

					if (Math.random() >= lambda) {
						if (hmacs.size() == 0)
							changeStateAsync(DetectionChannelState.CHANNEL_CLOSE);
						else
							changeStateAsync(DetectionChannelState.CHANNEL_FINAL);
					}
				} else {
					logger.info("Experiment - Detection - Mismatch: {}",//TODO:
							String.format("![%s] ![CHANNEL_OPEN] HMAC = ![%d]", flow.toString(), hmac.hashCode()));
					
//					logger.info("Debug - Record - Mismatch: {}",
//							String.format("CHANNEL_OPEN Current HMAC=%s", Arrays.toString(hmac)));
//					for (byte[] rhmac : hmacs)
//						logger.info("Debug - Record - Mismatch: {}",
//								String.format("CHANNEL_OPEN Record HMAC=%s", Arrays.toString(rhmac)));
					
					changeStateAsync(DetectionChannelState.CHANNEL_MISMATCH);
				}
				break;
				
			case CHANNEL_FINAL:
				// TODO: test for mismatch.
				if (Arrays.equals(hmacs.get(0), hmac)) {
//				pos = findHmacAsync(hmac);
//				if (pos >= 0) {
//					// TODO: test for mismatch
//					if (pos > 0) {
//						logger.info("Debug - Record - Out of Order: {}",
//								String.format("CHANNEL_FINAL Current HMAC=%s", Arrays.toString(hmac)));
//						for (byte[] rhmac : hmacs)
//							logger.info("Debug - Record - Out of Order: {}",
//									String.format("CHANNEL_FINAL Record HMAC=%s", Arrays.toString(rhmac)));
//					}
					
					logger.info("Experiment - Detection - Match: {}", String.format(
							"![%s] ![CHANNEL_FINAL] HMAC = ![%d], Record = ![%d]",
							flow.toString(), hmac.hashCode(), hmacs.get(0).hashCode()));
					
					hmacs.remove(0);
					timeouts.remove(0);
					
					logger.info("Debug - Record - Match: {}", String.format(
							"![%s] ![CHANNEL_FINAL] HMAC = ![%d], Size = ![%d]",
							flow.toString(), hmac.hashCode(), hmacs.size()));
					
					if (hmacs.size() == 0)
						changeStateAsync(DetectionChannelState.CHANNEL_CLOSE);
				} else {
					logger.info("Experiment - Detection - Mismatch: {}", // TODO:
							String.format("![%s] ![CHANNEL_FINAL] HMAC = ![%d]", flow.toString(), hmac.hashCode()));
					
//					logger.info("Debug - Record - Mismatch: {}",
//							String.format("CHANNEL_FINAL Current HMAC=%s", Arrays.toString(hmac)));
//					for (byte[] rhmac : hmacs)
//						logger.info("Debug - Record - Mismatch: {}",
//								String.format("CHANNEL_FINAL Record HMAC=%s", Arrays.toString(rhmac)));
					
					changeStateAsync(DetectionChannelState.CHANNEL_MISMATCH);
				}
				break;
				
			case CHANNEL_CLOSE:
			case CHANNEL_TIMEOUT:
			case CHANNEL_MISMATCH:
			default:
				return;
			}
		} finally {
			hmacsLock.unlock();
		}
	}
	
	public void setNextOpenTimeAsync(long time) {
		nextOpenTime = time;
	}
	
	public int randomOmega() {
		return (int) (Math.random() * (tao - 1)) + 1;
	}
	
	protected boolean hasTimeoutAsync(long timeout) {
		logger.info("Debug - Timeout Handler - Has Timeout: {} {}", timeout, timeouts.size());
		if (timeouts.size() > 0) {
			for (long t : timeouts) {
				logger.info("Debug - Timeout Handler - Has Timeout: {} {}", timeout, t);
			}
		}
		if (timeouts.size() == 0)
			return false;
		if (timeouts.get(0) <= timeout)
			return true;
		return false;
	}
	
	protected void clearHmacsAsync() {
		hmacs.clear();
		timeouts.clear();
	}
	
//	public void wakeChannel() {
//		try {
//			hmacsLock.lock();
//			if (state != DetectionChannelState.CHANNEL_CLOSE)
//				logger.info("Debug - Event - Wake Channel: {}", state.toString());
//			changeStateAsync(DetectionChannelState.CHANNEL_ESTABLISH);
//		} finally {
//			hmacsLock.unlock();
//		}
//	}
	
	protected int findHmacAsync(byte[] hmac) {
//		logger.info("Debug - Channel - Candidate HMAC: {}", Arrays.toString(hmac));
		for (int i = 0; i < hmacs.size(); i ++) {
//			logger.info("Debug - Channel - Record HMAC: {}", Arrays.toString(hmacs.get(i)));
			if (Arrays.equals(hmacs.get(i), hmac))
				return i;
		}
		
		return -1;
	}
	
	protected void changeStateAsync(DetectionChannelState newState) {
		logger.info("Experiment - Event - Channel State Changed: {}",
				String.format("![%s] ![%s] -> ![%s] ![%d]", flow.toString(), state.toString(), newState.toString(), System.currentTimeMillis()));
		
		finalState(state, newState);
		
		DetectionChannelState origState = state;
		state = newState;
		
		initState(origState, newState);
		
		dispatch(origState, newState);
	}
	
	protected void initState(DetectionChannelState prevState, DetectionChannelState curState) {
		logger.info("Debug - Channel - Channel State Initialize: {}",
				String.format("![%s] ![%s] -> ![%s]", flow.toString(), prevState.toString(), curState.toString()));
		
		switch (curState) {
		case CHANNEL_MISMATCH:
		case CHANNEL_TIMEOUT:
			clearHmacsAsync();
			break;
		
		case CHANNEL_ESTABLISH:
			currentAlpha = alpha;
		case CHANNEL_OPEN:
		case CHANNEL_FINAL:
		case CHANNEL_CLOSE:
		default:
			break;
		}
	}
	
	protected void finalState(DetectionChannelState curState, DetectionChannelState nextState) {
		logger.info("Debug - Channel - Channel State Finalize: {}",
				String.format("![%s] ![%s] -> ![%s]", flow.toString(), curState.toString(), nextState.toString()));
	}
	
	protected void dispatch(DetectionChannelState original, DetectionChannelState present) {
		eventHandlersLock.readLock().lock(); {
			for (IDetectionChannelEventHandler handler : eventHandlers)
				handler.detectionChannelStateChanged(flow, original, present);
		} eventHandlersLock.readLock().unlock();
	}
	
	public static void registerEventHandler(IDetectionChannelEventHandler handler) {
		logger.info("Experiment - Event - Register Event Handler: {}", String.format("![%s]", handler.toString()));
		
		eventHandlersLock.writeLock().lock(); {
			eventHandlers.add(handler);
		} eventHandlersLock.writeLock().unlock();
	}
	
	protected static class TimeoutHandler extends Thread {
		private List<List<DetectionChannel>> timeoutBuckets;
		private List<ReadWriteLock> timeoutBucketsLocks;
		
		private long latestTimeout;
		
		public TimeoutHandler() {
			timeoutBuckets      = new ArrayList<List<DetectionChannel>>();
			timeoutBucketsLocks = new ArrayList<ReadWriteLock>();
			for (int i = 0; i < bucketSize; i ++) {
				timeoutBuckets.add(new ArrayList<DetectionChannel>());
				timeoutBucketsLocks.add(new ReentrantReadWriteLock());
			}
			
			latestTimeout = System.currentTimeMillis();
		}
		
		public void addTimeout(DetectionChannel channel, long time) {
			int index =  ((int) (time/bucketSpan)) % bucketSize;
			
			logger.info("Debug - Timeout Handler - Add Timeout: {}",
					String.format("![%s] ![%d] ![%d]", channel.flow.toString(), time, index));
			
			timeoutBucketsLocks.get(index).readLock().lock(); {
				timeoutBuckets.get(index).add(channel);
			} timeoutBucketsLocks.get(index).readLock().unlock();
		}
		
		@Override
		public void run() {
			while (true) {
				try {
					long margin = System.currentTimeMillis() - latestTimeout;
					if (margin < bucketSpan) {
						Thread.sleep(bucketSpan - margin);
						continue;
					}
				} catch (InterruptedException e) {
					logger.error("Sleep Error: ", e);
				}
				
				logger.info("Debug - Timeout Handler - Wakeup: {}", String.format(
						"Current = ![%d], Latest = ![%d]", System.currentTimeMillis(), latestTimeout));
				
				int  index      = ((int) (latestTimeout/bucketSpan)) % bucketSize;
				long newTimeout = latestTimeout + bucketSpan;
				
				List<DetectionChannel> channels = timeoutBuckets.get(index);
				for (DetectionChannel channel : channels) {
					logger.info("Debug - Timeout Handler - Check: {}", String.format(
							"Timeout = ![%d] Index = ![%d] ![%s]", latestTimeout, index, channel.flow.toString()));
					
					channel.hmacsLock.lock(); {
						if (channel.hasTimeoutAsync(newTimeout)) {
							logger.info("Debug - Timeout Handler - Timeout Detected: {}", String.format(
									"Timeout = ![%d] Index = ![%d] ![%s]", latestTimeout, index, channel.flow.toString()));
							channel.changeStateAsync(DetectionChannelState.CHANNEL_TIMEOUT);
						}
					} channel.hmacsLock.unlock();
				}
				
				timeoutBucketsLocks.get(index).readLock().lock(); {
					timeoutBuckets.get(index).clear();
				} timeoutBucketsLocks.get(index).readLock().unlock();
				
				latestTimeout = newTimeout;
				logger.info("Debug - Timeout Handler - Sleep: {}", String.format(
						"Current = ![%d], Next = ![%d]", System.currentTimeMillis(), latestTimeout));
			}
		}
	}
}
