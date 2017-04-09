package cs4516.team4.dns;

import java.nio.ByteBuffer;

import net.floodlightcontroller.packet.BasePacket;
import net.floodlightcontroller.packet.IPacket;

public class DNS extends BasePacket {
	public static final int DNS_PORT = 53;

	private static final int TRANSACTION_ID_OFFSET = 0;
	private static final int FLAGS_OFFSET = TRANSACTION_ID_OFFSET + 2;
	private static final int QUESTION_COUNT_OFFSET = FLAGS_OFFSET + 2;
	private static final int ANSWER_COUNT_OFFSET = QUESTION_COUNT_OFFSET + 2;
	private static final int AUTHORITY_COUNT_OFFSET = ANSWER_COUNT_OFFSET + 2;
	private static final int ADDITIONAL_COUNT_OFFSET = AUTHORITY_COUNT_OFFSET + 2;
	private static final int QUERY_OFFSET = ADDITIONAL_COUNT_OFFSET + 2;

	/**
	 * Type of a DNS packet.
	 */
	public enum Type {
		QUERY, RESPONSE
	}

	/**
	 * Type of a DNS query.
	 */
	public enum Opcode {
		/**
		 * A standard query.
		 */
		QUERY,
		/**
		 * An inverse query (now obsolete).
		 */
		IQUERY,
		/**
		 * A server status request.
		 */
		STATUS,
		/**
		 * Notification from a primary server that data for a zone has changed.
		 */
		NOTIFY,
		/**
		 * Notification to add, delete or update records.
		 */
		UPDATE
	}

	/**
	 * The status of the DNS reply.
	 */
	public enum ReplyCode {
		/**
		 * No error occurred.
		 */
		NO_ERROR,
		/**
		 * The server was unable to respond to the query due to a problem with
		 * how it was constructed.
		 */
		FORMAT_ERROR,
		/**
		 * The server was unable to respond to the query due to a problem with
		 * the server itself.
		 */
		SERVER_FAILURE,
		/**
		 * The name specified in the query does not exist in the domain.
		 */
		NAME_ERROR,
		/**
		 * The type of query received is not supported by the server.
		 */
		NOT_IMPLEMENTED,
		/**
		 * The server refused to process the query, generally for policy reasons
		 * and not technical ones.
		 */
		REFUSED,
		/**
		 * A name exists when it should not.
		 */
		YX_DOMAIN,
		/**
		 * A resource record set exists that should not.
		 */
		YX_RR_SET,
		/**
		 * A response record set that should exist does not.
		 */
		NX_RR_SET,
		/**
		 * The server receiving the query is not authoritative for the zone
		 * specified.
		 */
		NOT_AUTH,
		/**
		 * A name specified in the message is not within the zone specified in
		 * the message.
		 */
		NOT_ZONE
	}

	private short transactionID;
	private byte[] flags;
	private short queryCount;
	private short answerCount;
	private short authorityCount;
	private short additionalCount;
	private DNSQuery[] queries;
	private DNSResource[] answers;
	private DNSResource[] authorities;
	private DNSResource[] additionals;

	/**
	 * Creates a new DNS packet from the given payload.
	 * 
	 * @param payload
	 *            The payload representing the DNS packet.
	 */
	public DNS(IPacket payload) {
		this(payload.serialize());
		setParent(payload.getParent());
	}

	/**
	 * Creates a new DNS packet.
	 * 
	 * @param data
	 *            The raw data of the packet.
	 */
	private DNS(byte[] data) {
		this(data, 0, data.length);
	}

	/**
	 * Creates a new DNS packet.
	 * 
	 * @param data
	 *            The raw data of the packet.
	 * @param offset
	 *            The offset for the data.
	 * @param length
	 *            The length of the data.
	 */
	private DNS(byte[] data, int offset, int length) {		
		ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);
		transactionID = buffer.getShort();
		flags = new byte[] { buffer.get(), buffer.get() };
		queryCount = buffer.getShort();
		answerCount = buffer.getShort();
		authorityCount = buffer.getShort();
		additionalCount = buffer.getShort();
		
		offset += buffer.position();
		queries = new DNSQuery[queryCount];
		for (int i = 0; i < queries.length; i++) {
			queries[i] = new DNSQuery(data, offset);
			offset += queries[i].getLength();
		}
		answers = new DNSResource[answerCount];
		for (int i = 0; i < answers.length; i++) {
			answers[i] = new DNSResource(data, offset);
			offset += answers[i].getLength();
		}
		authorities = new DNSResource[authorityCount];
		for (int i = 0; i < authorities.length; i++) {
			authorities[i] = new DNSResource(data, offset);
			offset += authorities[i].getLength();
		}
		additionals = new DNSResource[additionalCount];
		for (int i = 0; i < additionals.length; i++) {
			additionals[i] = new DNSResource(data, offset);
			offset += additionals[i].getLength();
		}
	}

	/**
	 * Gets the transaction ID of the packet.
	 * 
	 * @return the transaction ID.
	 */
	public int getTransactionID() {
		return transactionID;
	}

	/**
	 * Gets the flags of the packet.
	 * 
	 * @return The flags.
	 */
	public byte[] getFlags() {
		return flags;
	}

	/**
	 * Gets the type of the packet.
	 * 
	 * @return The DNS type.
	 */
	public Type getType() {
		return getFlags()[0] == 0x0 ? Type.QUERY : Type.RESPONSE;
	}

	/**
	 * Gets the type of the query.
	 * 
	 * @return The query type.
	 */
	public Opcode getOpcode() {
		switch (ByteBuffer.wrap(getFlags(), 1, 4).getInt()) {
		case 0:
			return Opcode.QUERY;
		case 1:
			return Opcode.IQUERY;
		case 2:
			return Opcode.STATUS;
		case 4:
			return Opcode.NOTIFY;
		case 5:
			return Opcode.UPDATE;
		default:
			return Opcode.QUERY;
		}
	}

	/**
	 * Gets the number of questions in the packet.
	 * 
	 * @return The number of questions.
	 */
	public int getQuestionCount() {
		return queryCount;
	}

	/**
	 * Gets the number of answers in the packet.
	 * 
	 * @return The number of answers.
	 */
	public int getAnswerCount() {
		return answerCount;
	}

	/**
	 * Gets the number of name servers in the packet.
	 * 
	 * @return The number of name servers.
	 */
	public int getAuthorityCount() {
		return authorityCount;
	}

	/**
	 * Gets the number of additional records in the packet.
	 * 
	 * @return The number of additional records.
	 */
	public int getAdditionalCount() {
		return additionalCount;
	}

	/**
	 * Gets the queries in the packet.
	 * 
	 * @return The queries.
	 */
	public DNSQuery[] getQueries() {
		return queries;
	}

	/**
	 * Gets the queries in the packet.
	 * 
	 * @return The queries.
	 */
	public DNSResource[] getAnswers() {
		return answers;
	}

	/**
	 * Gets the authorities in the packet.
	 * 
	 * @return The authorities.
	 */
	public DNSResource[] getAuthorities() {
		return authorities;
	}

	/**
	 * Gets the additional data in the packet.
	 * 
	 * @return The additional data.
	 */
	public DNSResource[] getAdditionals() {
		return additionals;
	}

	/**
	 * Gets the length of the data in this DNS packet.
	 * 
	 * @return The length of the data in bytes.
	 */
	public int getLength() {
		int length = QUERY_OFFSET;

		// add up all of the sections
		for (DNSSection[] section : new DNSSection[][] { queries, answers, authorities, additionals })
			for (int i = 0; i < section.length; i++)
				length += section[i].getLength();
		return length;
	}

	@Override
	public byte[] serialize() {
		byte[] data = new byte[getLength()];
		ByteBuffer buffer = ByteBuffer.wrap(data);
		// serialize all of the fields
		buffer.putShort(transactionID);
		buffer.put(flags);
		buffer.putShort(queryCount);
		buffer.putShort(answerCount);
		buffer.putShort(authorityCount);
		buffer.putShort(additionalCount);

		// serialize all of the sections
		for (DNSSection[] section : new DNSSection[][] { queries, answers, authorities, additionals })
			for (int i = 0; i < section.length; i++) 
				buffer.put(section[i].serialize());

		return data;
	}

	@Override
	public IPacket deserialize(byte[] data, int offset, int length) {
		return new DNS(data, offset, length);
	}
}
