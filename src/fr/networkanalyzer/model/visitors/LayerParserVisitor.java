package fr.networkanalyzer.model.visitors;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.exceptions.NetworkanalyzerParseErrorException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.Field;
import fr.networkanalyzer.model.fields.Fields;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.ILayerApplication;
import fr.networkanalyzer.model.layers.ILayerNetwork;
import fr.networkanalyzer.model.layers.ILayerTransport;
import fr.networkanalyzer.model.layers.protocols.Arp;
import fr.networkanalyzer.model.layers.protocols.Dhcp;
import fr.networkanalyzer.model.layers.protocols.Dns;
import fr.networkanalyzer.model.layers.protocols.Ethernet;
import fr.networkanalyzer.model.layers.protocols.Http;
import fr.networkanalyzer.model.layers.protocols.Icmp;
import fr.networkanalyzer.model.layers.protocols.Imap;
import fr.networkanalyzer.model.layers.protocols.Ip;
import fr.networkanalyzer.model.layers.protocols.Tcp;
import fr.networkanalyzer.model.layers.protocols.Udp;
import fr.networkanalyzer.model.tools.NetworkanalyzerTools;
import fr.networkanalyzer.model.tools.OptionsBuilder;
import fr.networkanalyzer.model.tools.ParsingTools;

public class LayerParserVisitor implements ILayerVisitor {

	private String line;
	private List<Integer> listIndex;
	private int currentIndex;
	private int index;
	private String header;

	public LayerParserVisitor() {
		listIndex = new ArrayList<>();
		currentIndex = 0;
		line = null;
		index = 0;
		header = null;
	}

	public void setLine(String line) {
		String data[] = line.split(" ");
		listIndex.clear();
		currentIndex = 0;
		index = 0;
		header = null;

		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < data.length; i++) {
			if (ParsingTools.isPattern(data[i])) {
				listIndex.add(ParsingTools.getIndexPattern(data[i]));
				continue;
			}

			sb.append(data[i].concat(" "));
		}

		this.line = sb.toString().trim();
	}

	@Override
	public void visit(Ethernet ethernet) throws NetworkAnalyzerException {

		header = getHeader(42).trim();

		String destMacAddress = parseField(Ethernet.DEST_ADDRESS);
		incIndex(Ethernet.DEST_ADDRESS);

		String srcMacAddress = parseField(Ethernet.SRC_ADDRESS);

		if (srcMacAddress.equals("FF FF FF FF FF FF"))
			throw new NetworkanalyzerParseErrorException(getLine(),
					"The source MAC address must not be a broadcast address");

		if (destMacAddress.equals(srcMacAddress))
			throw new NetworkanalyzerParseErrorException(getLine(), "Mac addresses are equal");

		incIndex(Ethernet.SRC_ADDRESS);

		String rdType = parseField(Ethernet.TYPE);

		IField type;
		ILayerNetwork layer = null;

		switch (rdType) {

		case Ethernet.IP: {
			layer = new Ip();
			type = new Field(Ethernet.TYPE, rdType, layer.getName());
			break;
		}

		case Ethernet.ARP: {
			layer = new Arp();
			type = new Field(Ethernet.TYPE, rdType, layer.getName());
			break;
		}

		default:
			throw new NetworkanalyzerParseErrorException(getLine(), "Unexpected value of the ethernet type field");
		}

		incIndex(Ethernet.TYPE);

		Field dest = new Field(Ethernet.DEST_ADDRESS, destMacAddress,
				destMacAddress.equals("FF FF FF FF FF FF") ? "broadcast" : destMacAddress.replace(" ", ":"));

		Field src = new Field(Ethernet.SRC_ADDRESS, srcMacAddress, srcMacAddress.replace(" ", ":"));

		ethernet.addField(Ethernet.SRC_ADDRESS.getName(), src);
		ethernet.addField(Ethernet.DEST_ADDRESS.getName(), dest);
		ethernet.addField(Ethernet.TYPE.getName(), type);

		layer.accept(this);
		ethernet.setIncluded(layer);
	}

	@Override
	public void visit(Ip ip) throws NetworkAnalyzerException {

		header = getHeader(60).trim();
		index = 0;

		String version = parseField(Ip.VERSION);

		if (!version.equals("4"))
			throw new NetworkanalyzerParseErrorException(getLine(), "The IP Vesion is not compatible");

		incIndex(Ip.VERSION);

		String ihl = parseField(Ip.IHL);

		int ihlDecoded = Integer.parseInt(ihl, 16);
		if (ihlDecoded < 5)
			throw new NetworkanalyzerParseErrorException(getLine(), "The IP IHL is not compatible");

		incIndex(Ip.IHL, true);

		String tos = parseField(Ip.TOS);
		incIndex(Ip.TOS);

		String totalLength = parseField(Ip.TOTAL_LENGTH);
		incIndex(Ip.TOTAL_LENGTH);

		String identification = parseField(Ip.IDENTIFICATION);
		incIndex(Ip.IDENTIFICATION);

		String fr = NetworkanalyzerTools.toBinary(parseField(Ip.FRAGMENTS));

		while (fr.length() != 16)
			fr = "0".concat(fr);

		String r = fr.substring(0, 1);
		String df = fr.substring(1, 2);
		String mf = fr.substring(2, 3);
		String fragmentOffset = fr.substring(3);

		incIndex(Ip.FRAGMENTS);

		String ttl = parseField(Ip.TTL);
		incIndex(Ip.TTL);

		String protocol = parseField(Ip.PROTOCOL);

		ILayerTransport layer;
		IField proto;

		switch (Integer.parseInt(protocol, 16)) {
		case Ip.ICMP: {
			layer = new Icmp();
			proto = new Field(Ip.PROTOCOL, protocol, layer.getName());
			break;
		}
		case Ip.UDP: {
			layer = new Udp();
			proto = new Field(Ip.PROTOCOL, protocol, layer.getName());
			break;
		}
		case Ip.TCP: {
			layer = new Tcp();
			proto = new Field(Ip.PROTOCOL, protocol, layer.getName());
			break;
		}
		default:
			throw new NetworkanalyzerParseErrorException(getLine(), "Unexpected value of the IP protocol field");
		}

		incIndex(Ip.PROTOCOL);

		String headerChecksum = parseField(Ip.HEADER_CHECKSUM);
		incIndex(Ip.HEADER_CHECKSUM);

		String srcAddress = parseField(Ip.SRC_ADDRESS);
		incIndex(Ip.SRC_ADDRESS);

		String destAddress = parseField(Ip.DEST_ADDRESS);

		if (srcAddress.equals("FF FF FF FF"))
			throw new NetworkanalyzerParseErrorException(getLine(),
					"The source IP address must not be a broadcast address");

		if (srcAddress.equals(destAddress))
			throw new NetworkanalyzerParseErrorException(getLine(), "IP addresses are equal");

		incIndex(Ip.DEST_ADDRESS);

		IField options = null;

		if (ihlDecoded > 5) {
			header = getHeader(((ihlDecoded - 5) * 12)).trim();
			options = OptionsBuilder.buildIpOptions(header);
		}

		currentIndex += (ihlDecoded - 5) * 12 + 12;
		index += (ihlDecoded - 5) * 12 + 12;

		ip.addField(Ip.DEST_ADDRESS.getName(),
				new Field(Ip.DEST_ADDRESS, destAddress, NetworkanalyzerTools.decodeAddressIp(destAddress)));

		ip.addField(Ip.SRC_ADDRESS.getName(),
				new Field(Ip.SRC_ADDRESS, srcAddress, NetworkanalyzerTools.decodeAddressIp(srcAddress)));

		ip.addField(Ip.PROTOCOL.getName(), proto);

		ip.addField(Ip.VERSION.getName(), new Field(Ip.VERSION, version, ip.getName()));

		ip.addField(Ip.IHL.getName(), new Field(Ip.IHL, ihl, String.valueOf(ihlDecoded)));

		ip.addField(Ip.TOS.getName(), new Field(Ip.TOS, tos, tos));

		ip.addField(Ip.TOTAL_LENGTH.getName(),
				new Field(Ip.TOTAL_LENGTH, totalLength, NetworkanalyzerTools.toInteger(totalLength)));

		ip.addField(Ip.IDENTIFICATION.getName(),
				new Field(Ip.IDENTIFICATION, identification, NetworkanalyzerTools.toInteger(identification)));

		Fields fragments = new Fields(Ip.FRAGMENTS.getName());
		fragments.addField(new Field(Ip.R, r, r));
		fragments.addField(new Field(Ip.DF, df, df));
		fragments.addField(new Field(Ip.MF, mf, mf));
		fragments.addField(
				new Field(Ip.FRAGMENT_OFFSET, fragmentOffset, NetworkanalyzerTools.toInteger(fragmentOffset, 2)));

		ip.addField(Ip.FRAGMENTS.getName(), fragments);

		ip.addField(Ip.TTL.getName(), new Field(Ip.TTL, ttl, NetworkanalyzerTools.toInteger(ttl)));
		ip.addField(Ip.HEADER_CHECKSUM.getName(), new Field(Ip.HEADER_CHECKSUM, headerChecksum, headerChecksum));

		if (options != null)
			ip.addField(Ip.OPTIONS.getName(), options);

		layer.accept(this);
		ip.setIncluded(layer);
	}

	@Override
	public void visit(Tcp tcp) throws NetworkAnalyzerException {
	}

	@Override
	public void visit(Udp udp) throws NetworkAnalyzerException {

		ILayerApplication layer;

		header = getHeader(24).trim();

		String srcPort = parseField(Udp.SRC_PORT);

		incIndex(Udp.SRC_PORT);
		String destPort = parseField(Udp.SRC_PORT);

		int pDest = Integer.parseInt(destPort.replace(" ", ""), 16);
		int pSrc = Integer.parseInt(srcPort.replace(" ", ""), 16);

//		if (pDest == pSrc && pSrc < 1024)
//			throw new NetworkanalyzerParseErrorException(getLine(), "Unexpected value of the Udp port fields");

		switch (pDest) {

		case Udp.DNS: {
			layer = new Dns();
			break;
		}

		default:
			if ((pDest == Udp.DHCP_1 && pSrc == Udp.DHCP_2) || (pDest == Udp.DHCP_2 && pSrc == Udp.DHCP_1)) {
				layer = new Dhcp();
				break;
			}

			throw new NetworkanalyzerParseErrorException(getLine(),
					"Unexpected value of the Udp port destination field");
		}

		incIndex(Udp.DEST_PORT);

		String length = parseField(Udp.LENGTH);
		incIndex(Udp.LENGTH);

		String checksum = parseField(Udp.CHECKSUM);
		incIndex(Udp.CHECKSUM);

		udp.addField(Udp.SRC_PORT.getName(),
				new Field(Udp.SRC_PORT, srcPort, String.valueOf(Integer.parseInt(srcPort.replace(" ", ""), 16))));

		udp.addField(Udp.DEST_PORT.getName(), new Field(Udp.DEST_PORT, destPort, String.valueOf(pDest)));

		udp.addField(Udp.LENGTH.getName(),
				new Field(Udp.LENGTH, length, String.valueOf(Integer.parseInt(length.replace(" ", ""), 16))));

		udp.addField(Udp.CHECKSUM.getName(),
				new Field(Udp.CHECKSUM, checksum, String.valueOf(Integer.parseInt(checksum.replace(" ", ""), 16))));

		layer.accept(this);
		udp.setIncluded(layer);
	}

	@Override
	public void visit(Dhcp dhcp) throws NetworkAnalyzerException {

		header = getHeader(708).trim();

		// message type------------------------------------------
		String messageType = parseField(Dhcp.MESSAGE_TYPE);
		String messageTypeDecoded = NetworkanalyzerTools.toInteger(messageType);

		if (!messageTypeDecoded.equals("1") && !messageTypeDecoded.equals("2"))
			throw new NetworkanalyzerParseErrorException(getLine(), "Unexpected value of the message type field");

		incIndex(Dhcp.MESSAGE_TYPE);
		dhcp.addField(Dhcp.MESSAGE_TYPE.getName(), new Field(Dhcp.MESSAGE_TYPE, messageType, messageTypeDecoded));

		// hardware type-----------------------------------------
		String hardwareType = parseField(Dhcp.HARDWARE_TYPE);
		incIndex(Dhcp.HARDWARE_TYPE);

		dhcp.addField(Dhcp.HARDWARE_TYPE.getName(),
				new Field(Dhcp.HARDWARE_TYPE, hardwareType, NetworkanalyzerTools.toInteger(hardwareType)));

		// hardware address length---------------------------------
		String hardwareAddressLenght = parseField(Dhcp.HARDWARE_ADDRESS_LENGTH);
		incIndex(Dhcp.HARDWARE_ADDRESS_LENGTH);

		dhcp.addField(Dhcp.HARDWARE_ADDRESS_LENGTH.getName(), new Field(Dhcp.HARDWARE_ADDRESS_LENGTH,
				hardwareAddressLenght, NetworkanalyzerTools.toInteger(hardwareAddressLenght)));

		// hops ---------------------------------------------------
		String hops = parseField(Dhcp.HOPS);
		incIndex(Dhcp.HOPS);

		dhcp.addField(Dhcp.HOPS.getName(), new Field(Dhcp.HOPS, hops, NetworkanalyzerTools.toInteger(hops)));
		// transaction ID
		String transactionId = parseField(Dhcp.TRANSACTION_ID);
		incIndex(Dhcp.TRANSACTION_ID);

		dhcp.addField(Dhcp.TRANSACTION_ID.getName(),
				new Field(Dhcp.TRANSACTION_ID, transactionId, NetworkanalyzerTools.toInteger(transactionId)));

		String secondsElapsed = parseField(Dhcp.SECONDS_ELAPSED);
		incIndex(Dhcp.SECONDS_ELAPSED);

		dhcp.addField(Dhcp.SECONDS_ELAPSED.getName(),
				new Field(Dhcp.SECONDS_ELAPSED, secondsElapsed, NetworkanalyzerTools.toInteger(secondsElapsed)));

		String fls = NetworkanalyzerTools.toBinary(parseField(Dhcp.FLAGS));
		incIndex(Dhcp.FLAGS);
		Fields flags = new Fields(Dhcp.FLAGS.getName());
		char broadcast = fls.charAt(0);
		flags.addField(new Field(Dhcp.BROADCAST, String.valueOf(broadcast), broadcast == '1' ? "true" : "false"));
		flags.addField(new Field(Dhcp.RESERVED, fls.substring(1), "0"));
		dhcp.addField(Dhcp.FLAGS.getName(), flags);

		String clientIp = parseField(Dhcp.CLIENT_IP_ADDRESS);
		incIndex(Dhcp.CLIENT_IP_ADDRESS);
		dhcp.addField(Dhcp.CLIENT_IP_ADDRESS.getName(),
				new Field(Dhcp.CLIENT_IP_ADDRESS, clientIp, NetworkanalyzerTools.decodeAddressIp(clientIp)));

		String yourIp = parseField(Dhcp.YOUR_IP_ADDRESS);
		incIndex(Dhcp.YOUR_IP_ADDRESS);
		dhcp.addField(Dhcp.YOUR_IP_ADDRESS.getName(),
				new Field(Dhcp.YOUR_IP_ADDRESS, yourIp, NetworkanalyzerTools.decodeAddressIp(yourIp)));

		String nextServerIp = parseField(Dhcp.NEXT_SERVER_IP_ADDRESS);
		incIndex(Dhcp.NEXT_SERVER_IP_ADDRESS);
		dhcp.addField(Dhcp.NEXT_SERVER_IP_ADDRESS.getName(), new Field(Dhcp.NEXT_SERVER_IP_ADDRESS, nextServerIp,
				NetworkanalyzerTools.decodeAddressIp(nextServerIp)));

		String relayAgent = parseField(Dhcp.RELAY_AGENT_IP_ADDRESS);
		incIndex(Dhcp.RELAY_AGENT_IP_ADDRESS);
		dhcp.addField(Dhcp.RELAY_AGENT_IP_ADDRESS.getName(),
				new Field(Dhcp.RELAY_AGENT_IP_ADDRESS, relayAgent, NetworkanalyzerTools.decodeAddressIp(relayAgent)));

		Dhcp.CLIENT_MAC_ADDRESS
				.setValue(Integer.parseInt(dhcp.getField(Dhcp.HARDWARE_ADDRESS_LENGTH.getName()).getValueDecoded()));
		String clientMac = parseField(Dhcp.CLIENT_MAC_ADDRESS);
		incIndex(Dhcp.CLIENT_MAC_ADDRESS);

		dhcp.addField(Dhcp.CLIENT_MAC_ADDRESS.getName(),
				new Field(Dhcp.CLIENT_MAC_ADDRESS, clientMac, clientMac.replace(" ", ":")));
		Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING
				.setValue(Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING.getValue() - Dhcp.CLIENT_MAC_ADDRESS.getValue());

		String padding = parseField(Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING);
		incIndex(Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING);

		dhcp.addField(Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING.getName(), new Field(Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING,
				padding, NetworkanalyzerTools.toInteger(padding), false));

		// TODO option overloading
		String serverHostName = parseField(Dhcp.SERVER_HOST_NAME);
		incIndex(Dhcp.SERVER_HOST_NAME);
		String result = NetworkanalyzerTools.toInteger(serverHostName).equals("0") ? "not given"
				: NetworkanalyzerTools.toAscii(serverHostName);

		dhcp.addField(Dhcp.SERVER_HOST_NAME.getName(), new Field(Dhcp.SERVER_HOST_NAME, serverHostName, result, false));

		String bootFile = parseField(Dhcp.SERVER_HOST_NAME);
		incIndex(Dhcp.SERVER_HOST_NAME);
		result = NetworkanalyzerTools.toInteger(bootFile).equals("0") ? "not given"
				: NetworkanalyzerTools.toAscii(bootFile);
		dhcp.addField(Dhcp.BOOT_FILE.getName(), new Field(Dhcp.BOOT_FILE, bootFile, "not given", false));

		// TODO MAGIC COOKIE ?
//		dhcp.addField(Dhcp.MAGIC_COOKIE.getName(), new Field(Dhcp.MAGIC_COOKIE, "63 82 53 63", "dhcp"));
	}

	@Override
	public void visit(Dns dns) throws NetworkAnalyzerException {

		header = getHeader(3).trim();
	}

	@Override
	public void visit(Arp arp) throws NetworkAnalyzerException {
	}

	@Override
	public void visit(Http http) throws NetworkAnalyzerException {
	}

	@Override
	public void visit(Icmp icmp) throws NetworkAnalyzerException {
	}

	@Override
	public void visit(Imap imap) throws NetworkAnalyzerException {
	}

	private int getLine() {

		for (int i = 0; i < listIndex.size(); i++) {
			if (currentIndex < listIndex.get(i))
				return i - 1;
		}

		throw new IndexOutOfBoundsException();
	}

	private String getHeader(int endIndex) throws NetworkanalyzerParseErrorException {
		if (line == null)
			throw new NetworkanalyzerParseErrorException();

		String header;

		try {
			header = line.substring(0, endIndex);
			line = line.substring(endIndex);
		} catch (IndexOutOfBoundsException e) {
			throw new NetworkanalyzerParseErrorException(getLine(), "The frame is not complete");
		}

		return header;
	}

	private String parseField(Entry entry) {

		int len = entry.getValue();
		int inc = 1;

		if (len % 8 == 0)
			inc = len / 4 + len / 8 - 1;

		return header.substring(index, index + inc);
	}

	private void incIndex(Entry entry, boolean end) {

		incIndex(entry);

		if (end) {
			currentIndex++;
			index++;
		}

	}

	private void incIndex(Entry entry) {

		int len = entry.getValue();
		int inc = 1;

		if (len % 8 == 0)
			inc = len / 4 + len / 8;

		currentIndex += inc;
		index += inc;
	}
}