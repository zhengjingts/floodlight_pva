package net.floodlightcontroller.pva;

public enum DetectionChannelState {
	/*
	 * Detection Channel State Machine:
	 *     CHANNEL_OPEN:
	 *     CHANNEL_CLOSE:
	 *     CHANNEL_ESTABLISH:
	 *     CHANNEL_FINAL:
	 */
	CHANNEL_OPEN     ,
	CHANNEL_CLOSE    ,
	CHANNEL_ESTABLISH,
	CHANNEL_FINAL    ,
	CHANNEL_TIMEOUT  ,
	CHANNEL_MISMATCH 
}
