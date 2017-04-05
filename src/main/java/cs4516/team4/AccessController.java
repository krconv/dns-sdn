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

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.IListener#getName()
	 */
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return null;
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
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#init(net.floodlightcontroller.core.module.FloodlightModuleContext)
	 */
	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#startUp(net.floodlightcontroller.core.module.FloodlightModuleContext)
	 */
	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub

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
						} else {
							// TODO: DROP PACKET
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

	private void rewriteIPforDNS(UDP packet, byte[] newIP) {
		byte[] rawPacket = packet.serialize();
		int udpHeaderSize = 8; // bytes
		int dnsHeaderSize = 18; // bytes

		// TODO: we may want to add a verification of the DNS response type to make sure we aren't overwriting packets that don't correspond with an A record

		int totalHead = udpHeaderSize + dnsHeaderSize;

		for (int i = 0; i < newIP.length; i++) {
			rawPacket[totalHead + i] = newIP[i];
		}

		packet.deserialize(rawPacket,0,packet.getLength());
	}
	private int extractTTLfromDNS(UDP packet) {
		byte[] rawPacket = packet.serialize();
		int udpHeaderSize = 8; // bytes
		int dnsOffset = 12; // bytes
		int offset = udpHeaderSize + dnsOffset;

		int result = 0;
		result += (rawPacket[offset+0] << 24);
		result += (rawPacket[offset+1] << 16);
		result += (rawPacket[offset+2] << 8);
		result += (rawPacket[offset+3]);

		return result;
	}

}
