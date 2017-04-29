/**
 * A DNS-based Capabilities Access Controller.
 */
package cs4516.team4;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
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
import org.projectfloodlight.openflow.types.TransportPort;
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
	private static MacAddress CLIENT_MAC_ADDRESS;
	private static MacAddress DNS_MAC_ADDRESS;
	private static MacAddress WEBSERVER_MAC_ADDRESS;
	private static String WEBSERVER_URL;
	private static int FLOW_IDLE_TIMEOUT;
	private static int NAT_IDLE_TIMEOUT;
	private static int FLOW_PRIORITY;

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
		if (!configParameters.containsKey("clientMACAddress"))
			throw new FloodlightModuleException("\"clientMACAddress\" not set in configuration!");
		if (!configParameters.containsKey("dnsMACAddress"))
			throw new FloodlightModuleException("\"dnsMACAddress\" not set in configuration!");
		if (!configParameters.containsKey("webserverMACAddress"))
			throw new FloodlightModuleException("\"webserverMACAddress\" not set in configuration!");
		if (!configParameters.containsKey("webserverURL"))
			throw new FloodlightModuleException("\"webserverURL\" not set in configuration!");
		if (!configParameters.containsKey("flowIdleTimeout"))
			throw new FloodlightModuleException("\"flowIdleTimeout\" not set in configuration!");
		if (!configParameters.containsKey("natIdleTimeout"))
			throw new FloodlightModuleException("\"natIdleTimeout\" not set in configuration!");
		if (!configParameters.containsKey("flowPriority"))
			throw new FloodlightModuleException("\"flowPriority\" not set in configuration!");

		CLIENT_MAC_ADDRESS = MacAddress.of(configParameters.get("clientMACAddress"));
		DNS_MAC_ADDRESS = MacAddress.of(configParameters.get("dnsMACAddress"));
		WEBSERVER_MAC_ADDRESS = MacAddress.of(configParameters.get("webserverMACAddress"));
		WEBSERVER_URL = configParameters.get("webserverURL");
		FLOW_IDLE_TIMEOUT = Integer.parseInt(configParameters.get("flowIdleTimeout"));
		NAT_IDLE_TIMEOUT = Integer.parseInt(configParameters.get("natIdleTimeout"));
		FLOW_PRIORITY = Integer.parseInt(configParameters.get("flowPriority"));
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

		if (ethernet.getEtherType() != EthType.IPv4) { // allow all non-IPv4 packets
			writeAllowFlow(sw, ethernet, true);
			return Command.STOP;
		}

		OFPacketIn packet = (OFPacketIn) msg;
		OFPort portIn = packet.getMatch().get(MatchField.IN_PORT);
		MacAddress sourceMac = ethernet.getSourceMACAddress();
		MacAddress destMac = ethernet.getDestinationMACAddress();
		IPv4 ip = (IPv4) ethernet.getPayload();
		IpProtocol protocol = ip.getProtocol();
		
		if (protocol == IpProtocol.TCP
				&& (sourceMac.equals(CLIENT_MAC_ADDRESS) || destMac.equals(CLIENT_MAC_ADDRESS))) {
			TCP tcp = (TCP) ip.getPayload();
			if (portIn == OFPort.LOCAL) { // message originating from client
				TransportPort sourcePort = tcp.getSourcePort();
				if (tcp.isSyn() && !tcp.isAck()) { 
					// create a NAT flow to map new connection to virtual IP
					logger.debug("[CLIENT] SYN packet sent to {}", ip.getDestinationAddress());
					IPv4Address modifiedIP = IPv4Address.of("10.45.4.48"); // NATManager.getInstance().addRecord(sourcePort,
													// NAT_IDLE_TIMEOUT);

					logger.debug("[CLIENT] Writing NAT flows mapping {} to {} from port {}",
							new Object[] { ip.getSourceAddress(), modifiedIP, sourcePort.getPort() });
					writeNATFlows(sw, ethernet, modifiedIP);

					return Command.STOP;
				}
			}
		} else if (protocol == IpProtocol.UDP
				&& (sourceMac.equals(DNS_MAC_ADDRESS) || destMac.equals(DNS_MAC_ADDRESS))) {
			if (portIn == OFPort.LOCAL) { // message originating from DNS server
				UDP udp = (UDP) ip.getPayload();
				if (udp.getSourcePort().getPort() == DNS.DNS_PORT) {

					// handle the DNS message
					DNS dns = new DNS(udp.getPayload());
					OFFactory factory = sw.getOFFactory();
	
					ArrayList<OFAction> actions = new ArrayList<OFAction>();
					// add an action to forward the packet
					actions.add(factory.actions().buildOutput().setPort(OFPort.ALL).build());
	
					if (dns.hasAnswer()) {
						logger.debug("[DNS] Response to " + dns.getQueries()[0].getName());
						if (dns.getQueries()[0].getName().equalsIgnoreCase(WEBSERVER_URL)) {
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
					}
	
					// forward the dns response
					sw.write(factory.buildPacketOut().setData(ethernet.serialize()).setActions(actions).build());
					return Command.STOP;
				}
			}
		} else if (protocol == IpProtocol.TCP
				&& (sourceMac.equals(WEBSERVER_MAC_ADDRESS) || destMac.equals(WEBSERVER_MAC_ADDRESS))) {
			if (portIn != OFPort.LOCAL) { // message originating from client
				TCP tcp = (TCP) ip.getPayload();
				if (tcp.getDestinationPort().getPort() == 80) { // http request
					IPv4Address address = ip.getDestinationAddress();
					CapabilitiesManager capabilities = CapabilitiesManager.getInstance();
					logger.debug("[WEB] Request to " + address);
	
					if (capabilities.verifyRecord(address) == CapabilitiesManager.Action.ALLOW) {
						// create a flow that will allow packets for the rest of the
						// capability life time with a FLOW_MOD
						logger.debug("[WEB] Request allowed");
						writeAllowFlow(sw, ethernet, capabilities.recordTimeLeft(address), true);
	
						return Command.STOP;
					} else {
						// create a flow that will drop packets
						logger.debug("[WEB] Request denied");
						writeDenyFlow(sw, ethernet);
						
						return Command.STOP;
					}
				}
			}
		}
		writeAllowFlow(sw, ethernet, true);
		return Command.STOP;
	}

	/**
	 * Writes the flows associated with the given NAT information.
	 * 
	 * @param sw
	 *            The switch to write to.
	 * @param original
	 *            The original IP address.
	 * @param modified
	 *            The virtual IP address.
	 * @param port
	 *            The source port to match.
	 */
	private void writeNATFlows(IOFSwitch sw, Ethernet ethernet, IPv4Address virtual) {
		// add outgoing flow
		OFFactory factory = sw.getOFFactory();
		List<OFAction> actionsOutbound = new ArrayList<OFAction>();
		actionsOutbound.add(factory.actions().setField(factory.oxms().ipv4Src(virtual)));
		actionsOutbound.add(factory.actions().buildOutput().setPort(OFPort.ALL).build());
		writeFlow(sw, createMatch(factory, ethernet, false), actionsOutbound, NAT_IDLE_TIMEOUT, FLOW_PRIORITY);
		// write the packet out
		sw.write(factory.buildPacketOut()
				.setData(ethernet.serialize())
				.setActions(actionsOutbound)
				.build());
		
		// add incoming flow
		IPv4 ip = ((IPv4) ethernet.getPayload());
		IPv4Address real = ip.getSourceAddress();
		ip.setSourceAddress(virtual).resetChecksum(); // change the source address so a match can be made
		List<OFAction> actionsInbound = new ArrayList<OFAction>();
		actionsInbound.add(factory.actions().setField(factory.oxms().ipv4Dst(real)));
		actionsInbound.add(factory.actions().buildOutput().setPort(OFPort.ALL).build());
		writeFlow(sw, createMatch(factory, ethernet, true), actionsInbound, NAT_IDLE_TIMEOUT, FLOW_PRIORITY);
	}
	
	/**
	 * Creates a match based on the given packet.
	 * @param factory A factory to create the match.
	 * @param ethernet The data link layer of the packet to match.
	 * @param reply Whether the match should be made for the given message or a reply to it.
	 * @return A match for the given packet.
	 */
	private Match createMatch(OFFactory factory, Ethernet ethernet, boolean reply) {
		Match.Builder mb = factory.buildMatch()
				.setExact(MatchField.ETH_TYPE, ethernet.getEtherType());
		
		if (ethernet.getEtherType() == EthType.IPv4) {
			IPv4 ip = (IPv4) ethernet.getPayload();
			mb.setExact(MatchField.IPV4_SRC, !reply ? ip.getSourceAddress() : ip.getDestinationAddress());
			mb.setExact(MatchField.IPV4_DST, !reply ? ip.getDestinationAddress() : ip.getSourceAddress());
			mb.setExact(MatchField.IP_PROTO, ip.getProtocol());

			// transport layer
			if (ip.getProtocol() == IpProtocol.TCP) {
				TCP tcp = (TCP) ip.getPayload();
				mb.setExact(MatchField.TCP_SRC, !reply ? tcp.getSourcePort() : tcp.getDestinationPort());
				mb.setExact(MatchField.TCP_DST, !reply ? tcp.getDestinationPort() : tcp.getSourcePort());
			} else if (ip.getProtocol() == IpProtocol.UDP) {
				UDP udp = (UDP) ip.getPayload();
				mb.setExact(MatchField.UDP_SRC, !reply ? udp.getSourcePort() : udp.getDestinationPort());
				mb.setExact(MatchField.UDP_DST, !reply ? udp.getDestinationPort() : udp.getSourcePort());
			}
		}		
		
		return mb.build();
	}

	/**
	 * Writes a flow that will allow packets for the default amount of time.
	 * @param sw The switch to write to.
	 * @param ethernet The data link layer of the packet to match.
	 */
	private void writeAllowFlow(IOFSwitch sw, Ethernet ethernet, boolean bidirectional) {
		writeAllowFlow(sw, ethernet, FLOW_IDLE_TIMEOUT, bidirectional);
	}
	
	/**
	 * Writes a flow that will allow packets matching the given one for the given amount of time.
	 * @param sw The switch to write to.
	 * @param ethernet The data link layer of the packet to match.
	 * @param timeout The hard timeout for the flow.
	 */
	private void writeAllowFlow(IOFSwitch sw, Ethernet ethernet, int timeout, boolean bidirectional) {
		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		OFFactory factory = sw.getOFFactory();
		
		actions.add(factory.actions().buildOutput().setPort(OFPort.ALL).build());
		
		writeFlow(sw, createMatch(factory, ethernet, false), actions, timeout);
		sw.write(factory.buildPacketOut().setData(ethernet.serialize()).setActions(actions).build());

		if (bidirectional)
			writeFlow(sw, createMatch(factory, ethernet, true), actions, timeout);
	}
	
	/**
	 * Writes a flow that will deny packets matching the given one for the default amount of time.
	 * @param sw The switch to write to.
	 * @param ethernet The data link layer of the packet to match.
	 */
	private void writeDenyFlow(IOFSwitch sw, Ethernet ethernet) {
		writeFlow(sw, createMatch(sw.getOFFactory(), ethernet, false), new ArrayList<OFAction>());
	}

	/**
	 * Writes a flow to the given switch.
	 * 
	 * @param sw
	 *            The switch to write to.
	 * @param match
	 *            The match for the flow.
	 * @param actions
	 *            The actions for the flow.
	 */
	private void writeFlow(IOFSwitch sw, Match match, List<OFAction> actions) {
		writeFlow(sw, match, actions, FLOW_IDLE_TIMEOUT);
	}

	/**
	 * Writes a flow to the given switch.
	 * 
	 * @param sw
	 *            The switch to write to.
	 * @param match
	 *            The match for the flow.
	 * @param actions
	 *            The actions for the flow.
	 * @param timeout
	 *            The hard timeout for the flow.
	 */
	private void writeFlow(IOFSwitch sw, Match match, List<OFAction> actions, int timeout) {
		writeFlow(sw, match, actions, timeout,
				actions == null || actions.isEmpty() ? FLOW_PRIORITY / 2 : FLOW_PRIORITY);
	}

	/**
	 * Writes a flow to the given switch.
	 * 
	 * @param sw
	 *            The switch to write to.
	 * @param match
	 *            The match for the flow.
	 * @param actions
	 *            The actions for the flow.
	 * @param timeout
	 *            The hard timeout for the flow.
	 * @param priority
	 *            The priority for the flow.
	 */
	private void writeFlow(IOFSwitch sw, Match match, List<OFAction> actions, int timeout, int priority) {
		OFFlowAdd flow = sw.getOFFactory().buildFlowAdd()
				.setMatch(match)
				.setActions(actions)
				.setBufferId(OFBufferId.NO_BUFFER)
				.setIdleTimeout(timeout)
				.setPriority(priority)
				.build();
		sw.write(flow);
	}
}
