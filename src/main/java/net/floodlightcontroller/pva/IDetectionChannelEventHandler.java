package net.floodlightcontroller.pva;

public interface IDetectionChannelEventHandler {
	
	public void detectionChannelStateChanged(Flow flow, DetectionChannelState original, DetectionChannelState present);
	
}
