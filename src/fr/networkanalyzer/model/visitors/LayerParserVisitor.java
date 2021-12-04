package fr.networkanalyzer.model.visitors;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.exceptions.NetworkanalyzerParseErrorException;
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

	public LayerParserVisitor() {
		listIndex = new ArrayList<>();
		currentIndex = 0;
		line = null;
	}

	public void setLine(String line) {
		String data[] = line.split(" ");
		listIndex.clear();
		currentIndex = 0;

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

		String header = getHeader(42).trim();

		System.out.println("Header ethernet : *" + header + "*");

		String destMacAddress = header.substring(0, 17);
		System.out.println("Mac dest : *" + destMacAddress + "*");
		String srcMacAddress = header.substring(18, 35);
		System.out.println("Mac src : *" + srcMacAddress + "*");
		String rdType = header.substring(36);
		System.out.println("type : *" + rdType + "*");

		IField type;
		ILayerNetwork layer = null;

		currentIndex += 18;
		if (srcMacAddress.equals("FF FF FF FF FF FF"))
			throw new NetworkanalyzerParseErrorException(getLine(),
					"The source MAC address must not be a broadcast address");

		if (destMacAddress.equals(srcMacAddress))
			throw new NetworkanalyzerParseErrorException(getLine(), "Mac addresses are equal");

		currentIndex += 18;

		switch (rdType) {

		case Ethernet.IP: {
			type = new Field(Ethernet.TYPE, rdType, "IPV4");
			layer = new Ip();
			break;
		}

		case Ethernet.ARP: {
			type = new Field(Ethernet.TYPE, rdType, "ARP");
			layer = new Arp();
			break;
		}

		default:
			throw new NetworkanalyzerParseErrorException(getLine(), "Unexpected value of the ethernet type field");
		}

		Field dest = new Field(Ethernet.DEST_ADDRESS, destMacAddress,
				destMacAddress.equals("FF FF FF FF FF FF") ? "broadcast" : destMacAddress.replace(" ", ":"));

		Field src = new Field(Ethernet.SRC_ADDRESS, srcMacAddress, srcMacAddress.replace(" ", ":"));

		ethernet.addField(Ethernet.SRC_ADDRESS.NAME, src);
		ethernet.addField(Ethernet.DEST_ADDRESS.NAME, dest);

		ethernet.addField(Ethernet.TYPE.NAME, type);

		currentIndex += 6;
		layer.accept(this);
		ethernet.setIncluded(layer);

	}

	@Override
	public void visit(Ip ip) throws NetworkAnalyzerException {

		String header = getHeader(60).trim();
		System.out.println("Header ip : *" + header + "*");

		String version = header.substring(0, 1);
		System.out.println("Version : *" + version + "*");
		if (!version.equals("4"))
			throw new NetworkanalyzerParseErrorException(getLine(), "The IP Vesion is not compatible");

		currentIndex += 1;

		String ihl = header.substring(1, 2);
		System.out.println("Ihl : *" + ihl + "*");
		currentIndex += 1;
		int ihlDecoded = Integer.parseInt(ihl, 16);
		if (ihlDecoded < 5)
			throw new NetworkanalyzerParseErrorException(getLine(), "The IP IHL is not compatible");

		String tos = header.substring(3, 5);
		System.out.println("Tos : *" + tos + "*");
		String totalLength = header.substring(6, 11);
		System.out.println("Total len : *" + totalLength + "*");
		String identification = header.substring(12, 17);
		System.out.println("Identific : *" + identification + "*");
		String fr = Integer.toBinaryString(Integer.parseInt(header.substring(18, 23).replace(" ", "")));
		System.out.println("Frags : *" + fr + "*");
		while (fr.length() != 16)
			fr = "0".concat(fr);

		String r = fr.substring(0, 1);
		String df = fr.substring(1, 2);
		String mf = fr.substring(2, 3);
		String fragmentOffset = fr.substring(3);

		String ttl = header.substring(24, 26);
		System.out.println("Ttl : *" + ttl + "*");
		String protocol = header.substring(27, 29);
		System.out.println("protocol : *" + protocol + "*");

		currentIndex += 25;

		ILayerTransport layer;
		IField proto;

		switch (Integer.parseInt(protocol, 16)) {
		case Ip.ICMP: {
			layer = new Icmp();
			proto = new Field(Ip.PROTOCOL, protocol, "ICMP");
			break;
		}
		case Ip.UDP: {
			layer = new Udp();
			proto = new Field(Ip.PROTOCOL, protocol, "UDP");
			break;
		}
		case Ip.TCP: {
			layer = new Tcp();
			proto = new Field(Ip.PROTOCOL, protocol, "TCP");
			break;
		}
		default:
			throw new NetworkanalyzerParseErrorException(getLine(), "Unexpected value of the IP protocol field");
		}

		String headerChecksum = header.substring(30, 35);
		System.out.println("checksum : *" + headerChecksum + "*");
		currentIndex += 9;

		String srcAddress = header.substring(36, 47);
		System.out.println("src ip addr : *" + srcAddress + "*");
		String destAddress = header.substring(48);
		System.out.println("dest ip addr : *" + destAddress + "*");

		if (srcAddress.equals("FF FF FF FF"))
			throw new NetworkanalyzerParseErrorException(getLine(),
					"The source IP address must not be a broadcast address");

		if (srcAddress.equals(destAddress))
			throw new NetworkanalyzerParseErrorException(getLine(), "IP addresses are equal");

		IField options = null;
		if (ihlDecoded > 5) {
			header = getHeader(((ihlDecoded - 5) * 12)).trim();
			System.out.println("*" + header + "*---->" + ihlDecoded);
			options = OptionsBuilder.buildIpOptions(header);
		}

		currentIndex += (ihlDecoded - 5) * 12 + 12;

		ip.addField(Ip.DEST_ADDRESS.NAME,
				new Field(Ip.DEST_ADDRESS, destAddress, NetworkanalyzerTools.decodeAddressIp(destAddress)));
		ip.addField(Ip.SRC_ADDRESS.NAME,
				new Field(Ip.SRC_ADDRESS, srcAddress, NetworkanalyzerTools.decodeAddressIp(srcAddress)));
		ip.addField(Ip.PROTOCOL.NAME, proto);

		ip.addField(Ip.VERSION.NAME, new Field(Ip.VERSION, version, "Ipv4"));
		ip.addField(Ip.IHL.NAME, new Field(Ip.IHL, ihl, String.valueOf(ihlDecoded)));
		ip.addField(Ip.TOS.NAME, new Field(Ip.TOS, tos, tos));
		ip.addField(Ip.TOTAL_LENGTH.NAME, new Field(Ip.TOTAL_LENGTH, totalLength,
				String.valueOf(Integer.parseInt(totalLength.replace(" ", ""), 16))));

		ip.addField(Ip.IDENTIFICATION.NAME, new Field(Ip.IDENTIFICATION, identification,
				String.valueOf(Integer.parseInt(identification.replace(" ", ""), 16))));

		Fields fragments = new Fields(Ip.FRAGMENTS.NAME);
		fragments.addField(new Field(Ip.R, r, r));
		fragments.addField(new Field(Ip.DF, df, df));
		fragments.addField(new Field(Ip.MF, mf, mf));
		fragments.addField(new Field(Ip.FRAGMENT_OFFSET, fragmentOffset,
				String.valueOf(Integer.parseInt(fragmentOffset.replace(" ", ""), 2))));

		ip.addField(Ip.FRAGMENTS.NAME, fragments);

		ip.addField(Ip.TTL.NAME, new Field(Ip.TTL, ttl, String.valueOf(Integer.parseInt(ttl.replace(" ", ""), 16))));
		ip.addField(Ip.HEADER_CHECKSUM.NAME, new Field(Ip.HEADER_CHECKSUM, headerChecksum, headerChecksum));

		if (options != null)
			ip.addField(Ip.OPTIONS.NAME, options);

		layer.accept(this);
		ip.setIncluded(layer);
	}

	@Override
	public void visit(Tcp tcp) throws NetworkAnalyzerException {
	}

	@Override
	public void visit(Udp udp) throws NetworkAnalyzerException {

		ILayerApplication layer;

		String header = getHeader(24).trim();
		System.out.println("Header udp : *" + header + "*");

		String srcPort = header.substring(0, 5);

		System.out.println("srcPort : *" + srcPort + "*");

		String destPort = header.substring(6, 11);

		System.out.println("destPort : *" + destPort + "*");

		int pDest = Integer.parseInt(destPort.replace(" ", ""), 16);
		int pSrc = Integer.parseInt(srcPort.replace(" ", ""), 16);

		currentIndex += 12;
		if (pDest == pSrc && pSrc > 1023)
			throw new NetworkanalyzerParseErrorException(getLine(), "Unexpected value of the Udp port fields");
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

		String length = header.substring(12, 17);

		System.out.println("udp length : *" + length + "*");
		String checksum = header.substring(18);

		System.out.println("udp checksum : *" + checksum + "*");

		udp.addField(Udp.SRC_PORT.NAME,
				new Field(Udp.SRC_PORT, srcPort, String.valueOf(Integer.parseInt(srcPort.replace(" ", ""), 16))));
		udp.addField(Udp.DEST_PORT.NAME, new Field(Udp.DEST_PORT, destPort, String.valueOf(pDest)));
		udp.addField(Udp.LENGTH.NAME,
				new Field(Udp.LENGTH, length, String.valueOf(Integer.parseInt(length.replace(" ", ""), 16))));
		udp.addField(Udp.CHECKSUM.NAME,
				new Field(Udp.CHECKSUM, checksum, String.valueOf(Integer.parseInt(checksum.replace(" ", ""), 16))));
		currentIndex += 12;

		layer.accept(this);
		udp.setIncluded(layer);
	}

	@Override
	public void visit(Arp arp) throws NetworkAnalyzerException {
	}

	@Override
	public void visit(Dhcp dhcp) throws NetworkAnalyzerException {

		String header = getHeader(708).trim();
		System.out.println("Header dhcp : *" + header + "*");

		String messageType = header.substring(0, 2);

		dhcp.addField(Dhcp.MESSAGE_TYPE.NAME, new Field(Dhcp.MESSAGE_TYPE, messageType, toIntegerValue(messageType)));

		String hardwareType = header.substring(3, 5);

		dhcp.addField(Dhcp.HARDWARE_TYPE.NAME,
				new Field(Dhcp.HARDWARE_TYPE, hardwareType, toIntegerValue(hardwareType)));

		String hardwareAddressLenght = header.substring(6, 8);

		dhcp.addField(Dhcp.HARDWARE_ADDRESS_LENGTH.NAME,
				new Field(Dhcp.HARDWARE_ADDRESS_LENGTH, hardwareAddressLenght, toIntegerValue(hardwareAddressLenght)));

		String hops = header.substring(9, 11);
		dhcp.addField(Dhcp.HOPS.NAME, new Field(Dhcp.HOPS, hops, toIntegerValue(hops)));

		String transactionId = header.substring(12, 23);
		dhcp.addField(Dhcp.TRANSACTION_ID.NAME,
				new Field(Dhcp.TRANSACTION_ID, transactionId, toIntegerValue(transactionId)));

		String secondsElapsed = header.substring(24, 29);
		dhcp.addField(Dhcp.SECONDS_ELAPSED.NAME,
				new Field(Dhcp.SECONDS_ELAPSED, secondsElapsed, toIntegerValue(secondsElapsed)));

		String fls = Integer.toBinaryString(Integer.parseInt(toIntegerValue(header.substring(30, 35))));

		Fields flags = new Fields(Dhcp.FLAGS.NAME);
		char broadcast = fls.charAt(0);
		flags.addField(new Field(Dhcp.BROADCAST, String.valueOf(broadcast), broadcast == '1' ? "true" : "false"));
		flags.addField(new Field(Dhcp.RESERVED, fls.substring(1), "0"));
		dhcp.addField(Dhcp.FLAGS.NAME, flags);

		String clientIp = header.substring(36, 47);
		dhcp.addField(Dhcp.CLIENT_IP_ADDRESS.NAME,
				new Field(Dhcp.CLIENT_IP_ADDRESS, clientIp, NetworkanalyzerTools.decodeAddressIp(clientIp)));

		String yourIp = header.substring(48, 59);
		dhcp.addField(Dhcp.YOUR_IP_ADDRESS.NAME,
				new Field(Dhcp.YOUR_IP_ADDRESS, yourIp, NetworkanalyzerTools.decodeAddressIp(yourIp)));

		String nextServerIp = header.substring(60, 71);
		dhcp.addField(Dhcp.NEXT_SERVER_IP_ADDRESS.NAME, new Field(Dhcp.NEXT_SERVER_IP_ADDRESS, nextServerIp,
				NetworkanalyzerTools.decodeAddressIp(nextServerIp)));

		String relayAgent = header.substring(72, 83);
		dhcp.addField(Dhcp.RELAY_AGENT_IP_ADDRESS.NAME,
				new Field(Dhcp.RELAY_AGENT_IP_ADDRESS, relayAgent, NetworkanalyzerTools.decodeAddressIp(relayAgent)));

		String clientMac = header.substring(84, 131);
		// TODO padding
		dhcp.addField(Dhcp.CLIENT_MAC_ADDRESS.NAME,
				new Field(Dhcp.CLIENT_MAC_ADDRESS, clientMac, clientMac.replace(" ", ":")));
//		dhcp.addField(Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING.NAME, new Field(Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING,
//				"00 00 00 00 00 00 00 00 00 00", "00 00 00 00 00 00 00 00 00 00"));

		// TODO option overloading
		String serverHostName = header.substring(132, 323);
		dhcp.addField(Dhcp.SERVER_HOST_NAME.NAME, new Field(Dhcp.SERVER_HOST_NAME, serverHostName, "not given", false));

		String bootFile = header.substring(324, 707);
		dhcp.addField(Dhcp.BOOT_FILE.NAME, new Field(Dhcp.BOOT_FILE, bootFile, "not given", false));

		// TODO MAGIC COOKIE ?
//		dhcp.addField(Dhcp.MAGIC_COOKIE.NAME, new Field(Dhcp.MAGIC_COOKIE, "63 82 53 63", "dhcp"));
	}

	@Override
	public void visit(Dns dns) throws NetworkAnalyzerException {
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

	private String toIntegerValue(String value) {
		return String.valueOf(Integer.parseInt(value.replace(" ", ""), 16));
	}
}