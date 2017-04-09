package cs4516.team4.dns;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.projectfloodlight.openflow.types.IPv4Address;

/**
 * @author Team 4
 */
public class DNSResource extends DNSSection {
	private static final int TTL_OFFSET = 0; // offset of the TTL field
	private static final int RESOURCE_LENGTH_OFFSET = TTL_OFFSET + 4; // offset
																		// of
																		// answer
	// length field
	private static final int RESOURCE_DATA_OFFSET = RESOURCE_LENGTH_OFFSET + 2; // offset
																				// of
																				// answer
																				// data
																				// field

	public enum ResourceType {
		/**
		 * Provides an unknown or unsupported answer.
		 */
		UNKNOWN,
		/**
		 * Resolves with a 32-bit IPv4 address.
		 */
		A,
		/**
		 * Specifies the name of a DNS names server that is authoritative for
		 * the queried zone.
		 */
		NS,
		/**
		 * Provides a mapping between this alias and the real name of the node.
		 */
		CNAME,
		/**
		 * Marks the start of a DNS zone and provides important information
		 * about it.
		 */
		SOA,
		/**
		 * Provides a pointer to another location in the name space.
		 */
		PTR,
		/**
		 * Specifies the location that is responsible for handling E-mails sent
		 * to the domain.
		 */
		MX,
		/**
		 * Provides arbitrary additional text associated with the domain.
		 */
		TXT,
		/**
		 * Resolves with a 128-bit IPv6 address.
		 */
		AAAA
	}

	private int ttl;
	private short resourceLength;
	private byte[] resourceData;

	/**
	 * Creates a DNS resource from the given data.
	 * 
	 * @param data
	 *            The data of the resource.
	 * @param offset
	 *            The offset of the resource data.
	 */
	DNSResource(byte[] data, int offset) {
		super(data, offset);
		offset += super.getLength();

		ByteBuffer buffer = ByteBuffer.wrap(data, offset, data.length - offset);
		ttl = buffer.getInt();
		resourceLength = buffer.getShort();
		resourceData = new byte[resourceLength];
		buffer.get(resourceData);
	}

	/**
	 * Gets the type of this answer.
	 * 
	 * @return The answer type.
	 */
	public ResourceType getResourceType() {
		switch (super.getType()) {
		case 1:
			return ResourceType.A;
		case 2:
			return ResourceType.NS;
		case 5:
			return ResourceType.CNAME;
		case 6:
			return ResourceType.SOA;
		case 12:
			return ResourceType.PTR;
		case 15:
			return ResourceType.MX;
		case 16:
			return ResourceType.TXT;
		case 28:
			return ResourceType.AAAA;
		default:
			return ResourceType.UNKNOWN;
		}
	}

	/**
	 * Gets the Time to Live of this resource.
	 * 
	 * @return The Time to Live in seconds.
	 */
	public int getTTL() {
		return ttl;
	}

	/**
	 * Gets the length of the resource data.
	 * 
	 * @return The length of the resource data in bytes.
	 */
	public short getResourceLength() {
		return resourceLength;
	}

	/**
	 * Gets the resource data.
	 * 
	 * @return The resource data.
	 */
	public byte[] getResourceData() {
		return resourceData;
	}

	/**
	 * Gets the resource data as an IPv4 address if this is an A type answer.
	 * 
	 * @return The IPv4 address if this is a A type answer, or otherwise null.
	 */
	public IPv4Address getIPv4Address() {
		if (getResourceType() == ResourceType.A)
			return IPv4Address.of(getResourceData());
		return null;
	}

	/**
	 * Sets the resource data as an IPv4 address if this is an A type answer.
	 * 
	 * @param address
	 *            The IPv4 address to set.
	 */
	public void setIPv4Address(IPv4Address address) {
		if (getResourceType() == ResourceType.A) {
			resourceData = Arrays.copyOf(address.getBytes(), getResourceLength());
		}
	}

	@Override
	protected int getLength() {
		return super.getLength() + RESOURCE_DATA_OFFSET + resourceLength;
	}

	@Override
	public byte[] serialize() {
		byte[] data = super.serialize();
		int offset = super.getLength();

		ByteBuffer buffer = ByteBuffer.wrap(data, offset, data.length - offset);
		buffer.putInt(ttl);
		buffer.putShort(resourceLength);
		buffer.put(resourceData);

		return data;
	}
}
