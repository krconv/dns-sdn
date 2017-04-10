/**
 * A DNS-based Capabilities Access Controller.
 */
package cs4516.team4;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import net.floodlightcontroller.packet.EthernetTest;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;

/**
 * @author Team 4
 */
public class AccessController implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	private MacAddress dnsMacAddress;
	private MacAddress webserverMacAddress;
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
		// TODO Auto-generated method stub
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
		// TODO Auto-generated method stub
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
		// TODO Auto-generated method stub
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
		// TODO Auto-generated method stub
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

		Map<String, String> configParameters = context.getConfigParams(this);
		if (!configParameters.containsKey("dnsMacAddress"))
			throw new FloodlightModuleException("\"dnsMacAddress\" not set in configuration!");
		else if (!configParameters.containsKey("webserverMacAddress"))
			throw new FloodlightModuleException("\"webserverMacAddress\" not set in configuration!");

		dnsMacAddress = MacAddress.of(configParameters.get("dnsMacAddress"));
		webserverMacAddress = MacAddress.of(configParameters.get("webserverMacAddress"));
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
		MacAddress sourceMac = ethernet.getSourceMACAddress();
		MacAddress destMac = ethernet.getDestinationMACAddress();

		if (ethernet.getEtherType() != EthType.IPv4)
			return Command.CONTINUE;

		logger.debug("Recieved PACKET_IN from switch on " + ((InetSocketAddress) sw.getInetAddress()).getHostName());

		IPv4 ip = (IPv4) ethernet.getPayload();
		IpProtocol protocol = ip.getProtocol();

		if (sourceMac.equals(dnsMacAddress) || destMac.equals(dnsMacAddress)) { // dns
																				// server
			if (protocol != IpProtocol.UDP)
				return Command.CONTINUE;

			UDP udp = (UDP) ip.getPayload();
			if (udp.getSourcePort().getPort() == DNS.DNS_PORT || udp.getDestinationPort().getPort() == DNS.DNS_PORT) {
				DNS dns = new DNS(udp.getPayload());
				OFFactory factory = sw.getOFFactory();
				logger.debug("DNS packet: " + dns.getType());
				if (dns.getType() == DNS.Type.RESPONSE) {
					if (dns.getAnswerCount() > 0) {
						logger.debug("Writing modified response...");
						DNSResource answer = dns.getAnswers()[0];
						answer.setIPv4Address(IPv4Address.of("1.2.3.4"));
					}
					udp.setPayload(dns);
					ArrayList<OFAction> actions = new ArrayList<OFAction>();
					actions.add(factory.actions().buildOutput() // builder pattern used throughout
							.setPort(OFPort.of(1)) // raw types replaced with objects for type-checking and readability
							.build()); // list of immutable OFAction objects
					sw.write(factory.buildPacketOut().setData(ethernet.serialize()).setActions(actions).build());
				} else if (dns.getType() == DNS.Type.QUERY) {
					logger.debug("Writing PACKET_MOD to allow incoming queries...");
					ArrayList<OFAction> actions = new ArrayList<OFAction>();
					actions.add(factory.actions().buildOutput() // builder pattern used throughout
							.setPort(OFPort.LOCAL) // raw types replaced with objects for type-checking and readability
							.build()); // list of immutable OFAction objects
					OFFlowAdd flow = factory.buildFlowAdd()
							.setMatch(factory.buildMatch()
									.setExact(MatchField.IN_PORT, OFPort.of(1))
									.build()) // immutable Match object
						.setPriority(100)
						.setActions(actions)
						.setBufferId(OFBufferId.NO_BUFFER)
						.setHardTimeout(10)
						.build(); // immutable OFFlowMod; no lengths to set; no wildcards to set
					sw.write(flow);

					sw.write(factory.buildPacketOut().setData(ethernet.serialize()).build());
				}
			}
		} else if (sourceMac.equals(webserverMacAddress) || destMac.equals(webserverMacAddress)) { // web
																									// server
			if (protocol != IpProtocol.TCP)
				return Command.CONTINUE;

			logger.debug("TCP");
			// if (CapabilitiesManager.getInstance()
			// .verifyRecord(dstIp.getBytes()) ==
			// CapabilitiesManager.Action.ALLOW) {
			// OFFactory factory = sw.getOFFactory();
			//
			// ArrayList<OFAction> actions = new ArrayList<OFAction>();
			// actions.add(factory.actions().buildOutput().setPort(OFPort.LOCAL).build());
			//
			// OFFlowAdd flow = factory.buildFlowAdd()
			// .setMatch(factory.buildMatch().setExact(MatchField.IN_PORT,
			// OFPort.of(1))
			// .setExact(MatchField.IPV4_SRC,
			// srcIp).setExact(MatchField.IPV4_DST, dstIp)
			// .build())
			// .setActions(actions).setOutPort(OFPort.of(2)).setBufferId(OFBufferId.NO_BUFFER)
			// .setHardTimeout(10).build();
			// sw.write(flow);
			//
			// } else {
			// // TODO: DROP PACKET
			// System.out.println("Dropping packet!");
			// }

		}
		return Command.CONTINUE;
	}
}
