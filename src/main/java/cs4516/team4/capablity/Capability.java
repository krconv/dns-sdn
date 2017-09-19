package cs4516.team4.capablity;

import java.util.Date;

import org.projectfloodlight.openflow.types.IPv4Address;

/**
 * An resource used to capture a hosts ability to connect to a protected host.
 * 
 * @author Team 4
 *
 */
public class Capability {
	private Date creation;
	private long ttl; // in milliseconds

	private IPv4Address address;

	/**
	 * Creates a new capability, capturing the authorized access from client to server.
	 * @param address The server that is access is being gained to.
	 * @param ttl The number of milliseconds that this capability is valid for.
	 */
	Capability(IPv4Address address, int ttl) {
		this.creation = new Date();
		
		this.address = address;
		
		this.ttl = ttl * 1000; // convert from seconds to milliseconds
	}

	/**
	 * Gets the virtual address used for access.
	 * @return The address.
	 */
	public IPv4Address getAddress() {
		return address;
	}
	
	/**
	 * Gets the Time to Live.
	 * @return The TTL in seconds.
	 */
	public int getTTL() {
		return (int) (ttl / 1000);
	}
	
	/**
	 * Gets the time left.
	 * @return The time left in seconds, or zero if expired.
	 */
	public int getTimeLeft() {
		int time = (int) ((creation.getTime() + ttl) - (new Date()).getTime()) / 1000;
		if (time < 0)
			return 0;
		return time;
	}
	
	/**
	 * Determines whether this capability has expired.
	 * @return Whether this capability has expired.
	 */
	public boolean isExpired() {
		return getTimeLeft() > 0;
	}
}
