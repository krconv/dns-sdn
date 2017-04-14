package cs4516.team4.capablity;

import java.util.HashMap;

import org.projectfloodlight.openflow.types.IPv4Address;

/**
 * A manager to keep track of given capabilities.
 * 
 * @author Team 4
 */
public class CapabilitiesManager {

	/**
	 * An action that should be taken.
	 */
	public enum Action {
		/**
		 * Allow the connection to proceed.
		 */
		ALLOW,
		/**
		 * Prevent the connection from proceeding.
		 */
		DROP
	}

	private static CapabilitiesManager instance = new CapabilitiesManager();

	/**
	 * Gets the instance of this manager.
	 * 
	 * @return The singleton instance.
	 */
	public static CapabilitiesManager getInstance() {
		return instance;
	}
	
	private HashMap<String, Capability> records = new HashMap<>(); // records stored [client -> capability]

	/**
	 * Adds a record for access from the current client.
	 * @param client The client gaining access.
	 * @param ttl The amount of time that the access should be granted for (seconds).
	 * @return The address that the client should use for access.
	 */
	public IPv4Address addRecord(int ttl) {
		IPv4Address address = generateIPInRange();
		records.put(address.toString(), new Capability(address, ttl));
		
		return address;
	}
	
	/**
	 * Determines how much longer an address can be accessed.
	 * @param address The address to check.
	 * @return The number of seconds left on the record, or zero if expired.
	 */
	public int recordTimeLeft(IPv4Address address) {
		Capability c = records.get(address.toString());
		if (c != null)
			return c.getTimeLeft();
		return 0;
	}


	/**
	 * Determines whether the given address can be accessed.
	 * @param address The address to check.
	 * @return Whether the address can be accessed.
	 */
	public Action verifyRecord(IPv4Address address) {
		return recordTimeLeft(address) > 0 ? Action.ALLOW : Action.DROP;
	}

	/**
	 * Creates a random IP address that hasn't been used.
	 * @return A random IP address in virtual address range.
	 */
	private IPv4Address generateIPInRange() {
		IPv4Address address;
		do {
			address = IPv4Address.of("10.45.4." + (int) (Math.random() * 128 + 128));
		} while (verifyRecord(address) == Action.ALLOW);
		
		return address;
	}

}
