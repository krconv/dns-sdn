package cs4516.team4;

import java.util.Date;

public class Capability {
	public Date creation;
	public long ttl; // in milliseconds

	public byte[] ip;

	public Capability(byte[] ip, long ttl){
		this.ip = ip;
		this.ttl = ttl;
		this.creation = new Date();
	}

	public boolean isExpired() {
		return (creation.getTime() + ttl) < (new Date()).getTime();
	}

}