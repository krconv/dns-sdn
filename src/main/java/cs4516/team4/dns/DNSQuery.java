/**
 * 
 */
package cs4516.team4.dns;

/**
 * @author Team 4
 */
public class DNSQuery extends DNSSection {
	
	/**
	 * Creates a DNS query from the given data.
	 * @param data The data of the query.
	 * @param offset The offset of the query data.
	 */
	DNSQuery(byte[] data, int offset) {
		super(data, offset);
	}
}
