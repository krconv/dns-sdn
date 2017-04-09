/**
 * 
 */
package cs4516.team4.dns;

import java.nio.ByteBuffer;

/**
 * @author Team 4
 */
public abstract class DNSSection {
	protected static final int MAX_LABEL_LENGTH = 63; // max number of
														// characters in a
														// domain name label

	private static final int NAME_OFFSET = 0; // offset of the name field
	private static final int TYPE_NAME_OFFSET = 0; // offset of type field after
													// name
	private static final int CLASS_NAME_OFFSET = TYPE_NAME_OFFSET + 2; // offset
																		// of
																		// class
																		// field
																		// after
																		// name

	private byte[] name;
	private short type;
	private short classValue;

	/**
	 * Creates a DNS section from the given data.
	 * 
	 * @param data
	 *            The data of the section.
	 * @param offset
	 *            The offset of the section data.
	 */
	DNSSection(byte[] data, int offset) {
		ByteBuffer buffer = ByteBuffer.wrap(data, offset, data.length - offset);
		name = new byte[getNameLength(data, offset + NAME_OFFSET)];
		buffer.get(name);
		type = buffer.getShort();
		classValue = buffer.getShort();
	}

	/**
	 * Gets the name in the query.
	 * 
	 * @return The name.
	 */
	public String getName() {
		return new String(name);
	}

	/**
	 * Gets the type of the query.
	 * 
	 * @return The type.
	 */
	public short getType() {
		return type;
	}

	/**
	 * Gets the class of the query.
	 * 
	 * @return The class.
	 */
	public short getClassValue() {
		return classValue;
	}

	/**
	 * Gets the length of the data for this section.
	 * 
	 * @return The length in bytes.
	 */
	protected int getLength() {
		return name.length + CLASS_NAME_OFFSET + 2;
	}

	/**
	 * Calculates the length of the DNS encoded domain name.
	 * 
	 * @param data
	 *            The data to parse.
	 * @param offset
	 *            The offset to the name.
	 * @return The length of the parsed name.
	 */
	private static int getNameLength(byte[] data, int offset) {
		if (Byte.toUnsignedInt(data[offset]) > MAX_LABEL_LENGTH)
			return 2; // dns shortcut, so fqdn isn't store multiple times

		int length = 0;
		while (data[offset + length] != 0x00) {
			length += Byte.toUnsignedInt(data[offset + length]) + 1;
		}
		return length + 1; // include null byte
	}
	
	/**
	 * Serialize the data into a byte array.
	 * 
	 * @return The serialized data.
	 */
	public byte[] serialize() {
		byte[] data = new byte[getLength()];
		
		ByteBuffer buffer = ByteBuffer.wrap(data);
		buffer.put(name);
		buffer.putShort(type);
		buffer.putShort(classValue);
		return data;
	}
}
