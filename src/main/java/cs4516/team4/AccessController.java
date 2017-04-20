/**
 * A DNS-based Capabilities Access Controller.
 */
package cs4516.team4;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cs4516.team4.capablity.CapabilitiesManager;
import cs4516.team4.dns.DNS;
import cs4516.team4.dns.DNSResource;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.TCP;

/**
 * @author Team 4
 */
public class AccessController implements IOFMessageListener, IFloodlightModule {
	private static MacAddress DNS_MAC_ADDRESS;
	private static MacAddress WEBSERVER_MAC_ADDRESS;
	private static int DEFAULT_BLOCK_TIME;

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;

	/*
	 * (non-Javadoc)
	 * 
	 * @see net.floodlightcontroller.core.IListener#getName()
	 */
	@Override
	public String getName() {
		return AccessController.class.getSimpleName();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * net.floodlightcontroller.core.IListener#isCallbackOrderingPrereq(java.
	 * lang.Object, java.lang.String)
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * net.floodlightcontroller.core.IListener#isCallbackOrderingPostreq(java.
	 * lang.Object, java.lang.String)
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * net.floodlightcontroller.core.module.IFloodlightModule#getModuleServices(
	 * )
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * net.floodlightcontroller.core.module.IFloodlightModule#getServiceImpls()
	 */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#
	 * getModuleDependencies()
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#init(net.
	 * floodlightcontroller.core.module.FloodlightModuleContext)
	 */
	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		logger = LoggerFactory.getLogger(AccessController.class);

		// check the configuration for the the set MAC addresses
		Map<String, String> configParameters = context.getConfigParams(this);
		logger.debug(Arrays.toString(configParameters.keySet().toArray()));
		if (!configParameters.containsKey("dnsMACAddress"))
			throw new FloodlightModuleException("\"dnsMACAddress\" not set in configuration!");
		else if (!configParameters.containsKey("webserverMACAddress"))
			throw new FloodlightModuleException("\"webserverMACAddress\" not set in configuration!");
		else if (!configParameters.containsKey("defaultBlockTime"))
			throw new FloodlightModuleException("\"defaultBlockTime\" not set in configuration!");
		
		DNS_MAC_ADDRESS = MacAddress.of(configParameters.get("dnsMACAddress"));
		WEBSERVER_MAC_ADDRESS = MacAddress.of(configParameters.get("webserverMACAddress"));
		DEFAULT_BLOCK_TIME = Integer.parseInt(configParameters.get("defaultBlockTime"));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#startUp(net.
	 * floodlightcontroller.core.module.FloodlightModuleContext)
	 */
	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	/**
	 * Handles a PACKET_IN message.
	 * 
	 * @param sw
	 *            The switch that sent the message.
	 * @param msg
	 *            The message to handle.
	 * @param cntx
	 *            The Floodlight context.
	 * 
	 * @return A command determining whether the message should be processed
	 *         further.
	 */
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		Ethernet ethernet = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		if (ethernet.getEtherType() != EthType.IPv4)
			return Command.CONTINUE;

		MacAddress sourceMac = ethernet.getSourceMACAddress();
		MacAddress destMac = ethernet.getDestinationMACAddress();
		IPv4 ip = (IPv4) ethernet.getPayload();
		IpProtocol protocol = ip.getProtocol();
		OFPort portIn = ((OFPacketIn) msg).getMatch().get(MatchField.IN_PORT);

		if (protocol == IpProtocol.UDP && (sourceMac.equals(DNS_MAC_ADDRESS) || destMac.equals(DNS_MAC_ADDRESS))) { // dns server
			if (portIn == OFPort.LOCAL) { // message originating from DNS server
				UDP udp = (UDP) ip.getPayload();
				if (udp.getSourcePort().getPort() != DNS.DNS_PORT)
					return Command.CONTINUE; // not a dns message

				// handle the DNS message
				DNS dns = new DNS(udp.getPayload());
				OFFactory factory = sw.getOFFactory();

				ArrayList<OFAction> actions = new ArrayList<OFAction>();
				// add an action to forward the packet
				actions.add(factory.actions().buildOutput().setPort(OFPort.of(1)).build());

				if (dns.hasAnswer()) {
					logger.debug("[DNS] Response to " + dns.getQueries()[0].getName());
					boolean modified = false;
					for (DNSResource answer : dns.getAnswers()) {
						if (answer.getResourceType() == DNSResource.ResourceType.A) {
							modified = true;
							IPv4Address modifiedIP = CapabilitiesManager.getInstance().addRecord(answer.getTTL());
							logger.debug("[DNS] Response changed from " + answer.getIPv4Address() + " to " + modifiedIP
									+ " (TTL: " + answer.getTTL() + ")");
							answer.setIPv4Address(modifiedIP);
						}
					}

					// update packet checksum if modified
					if (modified) {
						udp.setPayload(dns);
						dns.resetChecksum();
					}
				}

				// forward the dns response
				sw.write(factory.buildPacketOut().setData(ethernet.serialize()).setActions(actions).build());
				return Command.STOP;
			}
		} else if (protocol == IpProtocol.TCP && (sourceMac.equals(WEBSERVER_MAC_ADDRESS) || destMac.equals(WEBSERVER_MAC_ADDRESS))) { // web server
			if (portIn != OFPort.LOCAL) { // message originating from client
				TCP tcp = (TCP) ip.getPayload();
				if (tcp.getDestinationPort().getPort() != 80)
					return Command.CONTINUE;
				IPv4Address address = ip.getDestinationAddress();
				CapabilitiesManager capabilities = CapabilitiesManager.getInstance();
				logger.debug("[WEB] Request to " + address);

				OFFactory factory = sw.getOFFactory();
				ArrayList<OFAction> actions = new ArrayList<OFAction>();
				if (capabilities.verifyRecord(address) == CapabilitiesManager.Action.ALLOW) {
					logger.debug("[WEB] Request allowed");
					// add an action to forward the packet
					actions.add(factory.actions().buildOutput().setPort(OFPort.LOCAL).build());

					// create a flow that will allow packets for the rest of the
					// capability life time with a FLOW_MOD
					Match match = factory.buildMatch()
							.setExact(MatchField.ETH_TYPE, EthType.IPv4)
							.setExact(MatchField.IPV4_SRC, ip.getSourceAddress())
							.setExact(MatchField.IPV4_DST, address)
							.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
							.setExact(MatchField.TCP_DST, tcp.getDestinationPort())
							.build();
					OFFlowAdd flow = factory.buildFlowAdd()
							.setMatch(match)
							.setActions(actions)
							.setOutPort(OFPort.LOCAL)
							.setBufferId(OFBufferId.NO_BUFFER)
							.setHardTimeout(capabilities.recordTimeLeft(address)).build();
					sw.write(flow);

					// allow the processed packet to flow with a PACKET_OUT
					sw.write(factory.buildPacketOut().setData(ethernet.serialize()).setActions(actions).build());
					return Command.STOP;
				} else {
					logger.debug("[WEB] Request denied");
					// create a flow that will allow packets for the rest of the
					// capability life time with a FLOW_MOD
					Match match = factory.buildMatch()
							.setExact(MatchField.ETH_TYPE, EthType.IPv4)
							.setExact(MatchField.IPV4_SRC, ip.getSourceAddress())
							.setExact(MatchField.IPV4_DST, address)
							.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
							.setExact(MatchField.TCP_DST, tcp.getDestinationPort())
							.build();
					OFFlowAdd flow = factory.buildFlowAdd()
							.setMatch(match)
							.setActions(actions)
							.setBufferId(OFBufferId.NO_BUFFER)
							.setHardTimeout(DEFAULT_BLOCK_TIME).build();
					sw.write(flow);
					return Command.STOP;
				}
			}
		}
		return Command.CONTINUE;
	}
}
