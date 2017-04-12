
package cs4516.team4;

import java.util.HashMap;

public class CapabilitiesManager {

	public enum Action {
		ALLOW,DROP
	}

	private static CapabilitiesManager instance = new CapabilitiesManager();
	public static CapabilitiesManager getInstance(){
		return instance;
	}


	private HashMap<byte[],Capability> records = new HashMap<>(); 

	// Returns generated IP for destination
	// TTL in milliseconds
	public byte[] addRecord(long ttl) {
		byte[] ip = generateIPInRange();

		Capability c = new Capability(ip,ttl);
		records.put(ip,c);

		return ip;
	}

	public Action verifyRecord(byte[] ip) {
		Capability c = records.get(ip);
		if (c != null && !c.isExpired()) 
			return Action.ALLOW;
		return Action.DROP;
	}

	private byte[] generateIPInRange(){
		byte[] ip = new byte[4];
		ip[0] = 0xA;  // 10
		ip[1] = 0x2D; // 45
		ip[2] = 0x4;  // 4
		ip[3] = (byte)Math.floor(Math.random() * 128 + 127);
		return ip;
	}

}