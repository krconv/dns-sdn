public class NATManager {
	private static NATManager mgr = new NATManager();
	public static NATManager getInstance(){
		return mgr;
	}

	private HashSet<NATEntry> natEntries = new HashSet<>();

	public void addEntry(NATEntry e) {
		natEntries.put(e);
	}

	public List<NATEntry> entriesForSourceAddr(IPv4Address src) {
		NATEntry e = new NATEntry();
		e.srcAddr = src;

		List<NATEntry> matches = matching(e);
		return matches;
	}


	public void removeEntriesMatching(NATEntry match) {
		List<NATEntry> matches = matching(match);
		for (NATEntry e : matches) {
			natEntries.remove(e);
		}
	}

	// Returns list of entries that match the match argument
	// If PORT = -1, it is wildcarded and will match any port
	// If IP = null, it is wildcarded and will match any IP
	public List<NATEntry> matching(NATEntry match) {
		List<NATEntry> list = new LinkedList<>();
		for (NATEntry entry : natEntries) {
			if (match.srcAddr != null && !match.srcAddr.toString().equals(entry.srcAddr)) 
				continue;
			if (match.dstAddr != null && !match.dstAddr.toString().equals(entry.dstAddr)) 
				continue;
			if (match.srcPort != -1 && match.srcPort != entry.srcPort) 
				continue;
			if (match.dstPort != -1 && match.dstPort != entry.dstPort) 
				continue;
			
			list.add(entry);

		}

		return list;
	}

	private IPv4Address generateIPInRange(){
		return IPv4Address.of("10.45.4." + (int) (Math.random() * 128 + 128));
	}
	
	private long generatePortInRange() {
		return (long)Math.floor(Math.random() * 1000 + 2000);
	}


}