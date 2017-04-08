/**
 * 
 */
package cs4516.team4;

import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

/**
 * @author Team 4
 *
 */
public class AccessController implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.IListener#getName()
	 */
	@Override
	public String getName() {
		return MACTracker.class.getSimpleName();
	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.IListener#isCallbackOrderingPrereq(java.lang.Object, java.lang.String)
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.IListener#isCallbackOrderingPostreq(java.lang.Object, java.lang.String)
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#getModuleServices()
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#getServiceImpls()
	 */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#getModuleDependencies()
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
        	new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    return l;
	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#init(net.floodlightcontroller.core.module.FloodlightModuleContext)
	 */
	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    macAddresses = new ConcurrentSkipListSet<Long>();
	    logger = LoggerFactory.getLogger(MACTracker.class);

	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#startUp(net.floodlightcontroller.core.module.FloodlightModuleContext)
	 */
	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

	}



	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.IOFMessageListener#receive(net.floodlightcontroller.core.IOFSwitch, org.projectfloodlight.openflow.protocol.OFMessage, net.floodlightcontroller.core.FloodlightContext)
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
			FloodlightContext cntx) {

		switch (msg.getType()) {
			case PACKET_IN:
				Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		 
				MacAddress srcMac = eth.getSourceMACAddress();
				VlanVid vlanId = VlanVid.ofVlan(eth.getVlanID());
		 
				if (eth.getEtherType() == EthType.IPv4) {
					IPv4 ipv4 = (IPv4) eth.getPayload();
					 
					byte[] ipOptions = ipv4.getOptions();
					IPv4Address dstIp = ipv4.getDestinationAddress();
					 
					if (ipv4.getProtocol() == IpProtocol.TCP) {
						TCP tcp = (TCP) ipv4.getPayload();
		  
						TransportPort srcPort = tcp.getSourcePort();
						TransportPort dstPort = tcp.getDestinationPort();
						short flags = tcp.getFlags();
						 

						if (CapabilitiesManager.getInstance().verifyRecord(dstIp) == CapabilitiesManager.Action.ALLOW) {
							// TODO: ALLOW PACKET
							System.out.println("Allowing packet to flow");
						} else {
							// TODO: DROP PACKET
							System.out.println("Dropping packet!");
						}
						
					} else if (ipv4.getProtocol() == IpProtocol.UDP) {
						UDP udp = (UDP) ipv4.getPayload();
		  
						TransportPort srcPort = udp.getSourcePort();
						TransportPort dstPort = udp.getDestinationPort();
						
						
						long ttl = extractTTLfromDNS(udp);

						byte[] newIP = CapabilitiesManager.getInstance().addRecord(ttl);

						rewriteIPforDNS(udp,newIP);

						// TODO: send PACKET_OUT with modified DNS
						
					}
		 
				} else if (eth.getEtherType() == EthType.ARP) {
					
					ARP arp = (ARP) eth.getPayload();
		 
					
					boolean gratuitous = arp.isGratuitous();
		 
				} else {
					// Not sure
				}
				break;
			default:
				break;
		}
		return Command.CONTINUE;
	}

		
	private static final int UDP_HEAD_SIZE = 8; // bytes
	private static final int DNS_OFFSET_DATA = 10; // bytes after name
	private static final int DNS_OFFSET_TTL = 4; // bytes after name

	private void rewriteIPforDNS(UDP packet, byte[] newIP) {
		byte[] rawPacket = packet.serialize();
		int dnsHeaderSize = DNS_OFFSET_DATA + getDNSNameSize(rawPacket); // bytes

		// TODO: we may want to add a verification of the DNS response type to make sure we aren't overwriting packets that don't correspond with an A record

		int totalHead = UDP_HEAD_SIZE + dnsHeaderSize;

		for (int i = 0; i < newIP.length; i++) {
			rawPacket[totalHead + i] = newIP[i];
		}

		packet.deserialize(rawPacket,0,packet.getLength());
	}
	private int extractTTLfromDNS(UDP packet) {
		byte[] rawPacket = packet.serialize();
		int dnsOffset = DNS_OFFSET_TTL + getDNSNameSize(rawPacket); // bytes
		int offset = UDP_HEAD_SIZE + dnsOffset;

		int result = 0;
		result += (rawPacket[offset+0] << 24);
		result += (rawPacket[offset+1] << 16);
		result += (rawPacket[offset+2] << 8);
		result += (rawPacket[offset+3]);

		return result;
	}
	private byte[] getDNSNameSize(byte[] rawPacket) {
		int i = UDP_HEAD_SIZE;
		byte current = rawPacket[i];
		while (current != 0x00) {
			current = rawPacket[++i];
		}
		return i + 1 - UDP_HEAD_SIZE;
	}

}
