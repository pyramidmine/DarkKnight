package common;

public class Statistics {
	public long encryptLength;
	public long encryptCount;
	public long encryptTime;
	public long encodeLength;
	public long encodeCount;
	public long encodeTime;
	
	public void reset()
	{
		this.encryptLength = 0;
		this.encryptCount = 0;
		this.encryptTime = 0;
		this.encodeLength = 0;
		this.encodeCount = 0;
		this.encodeTime = 0;
	}
}
