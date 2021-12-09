package fr.networkanalyzer.model.visitors;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import fr.networkanalyzer.model.decoder.ArpDecoder;
import fr.networkanalyzer.model.decoder.DnsDecoder;
import fr.networkanalyzer.model.decoder.HardwareDecoder;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.exceptions.NetworkanalyzerParseErrorException;
import fr.networkanalyzer.model.exceptions.NetworkanalyzerParseWarningException;
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
import fr.networkanalyzer.model.layers.protocols.Icmp;
import fr.networkanalyzer.model.layers.protocols.Ip;
import fr.networkanalyzer.model.layers.protocols.Udp;
import fr.networkanalyzer.model.options.OptionsBuilder;
import fr.networkanalyzer.model.tools.NetworkanalyzerTools;
import fr.networkanalyzer.model.tools.ParsingTools;

public class LayerParserVisitor implements ILayerVisitor {

	private String line;
	private List<List<Integer>> listIndex;
	private int currentIndex;
	private int index;
	private String header;
	private int lastIndex;

	public LayerParserVisitor() {
		listIndex = new ArrayList<>();
		currentIndex = 0;
		line = null;
		index = 0;
		header = null;
		lastIndex = 0;
	}

	public void setLine(String line) {
		String data[] = line.split(" ");

		index = 0;
		header = null;

		StringBuilder sb = new StringBuilder();

		lastIndex = Integer.parseInt(data[data.length - 1]);

		for (int i = 0; i < data.length - 1; i++) {
			if (ParsingTools.isPattern(data[i])) {
				listIndex.add(
						Arrays.asList(ParsingTools.getIndexPattern(data[i]), ParsingTools.getLinePattern(data[i])));

				continue;
			}

			sb.append(data[i].concat(" "));
		}

		Collections.sort(listIndex, new Comparator<List<Integer>>() {

			@Override
			public int compare(List<Integer> o1, List<Integer> o2) {

				return o1.get(0) - o2.get(0);
			}
		});

		this.line = sb.toString().strip().concat(" ");
	}

	@Override
	public void visit(Ethernet ethernet) throws NetworkAnalyzerException {
		header = getHeader(42).trim();

		String destMacAddress = parseField(Ethernet.DEST_ADDRESS);
		incIndex(Ethernet.DEST_ADDRESS);

		String srcMacAddress = parseField(Ethernet.SRC_ADDRESS);

		if (srcMacAddress.equals("FF FF FF FF FF FF")) {

			int lineError = getLine();
			moveToNextFrameIndex();
			throw new NetworkanalyzerParseErrorException(lineError,
					"The source MAC address must not be a broadcast address");
		}

		if (destMacAddress.equals(srcMacAddress) && !destMacAddress.equals("00 00 00 00 00 00")) {
			int lineError = getLine();
			moveToNextFrameIndex();
			throw new NetworkanalyzerParseErrorException(lineError, "Mac addresses are equal");
		}

		incIndex(Ethernet.SRC_ADDRESS);

		String rdType = parseField(Ethernet.TYPE);

		IField type = null;
		ILayerNetwork layer = null;
		boolean isData = false;
		int indexWarning = 0;
		switch (rdType) {

		case Ethernet.IPV4: {
			layer = new Ip();
			type = new Field(Ethernet.TYPE, rdType, layer.getName());
			break;
		}

		case Ethernet.ARP: {
			layer = new Arp();
			type = new Field(Ethernet.TYPE, rdType, layer.getName());
			break;
		}

		case Ethernet.IPV6: {
			isData = true;
			indexWarning = getLine();
			moveToNextFrameIndex();
			type = new Field(Ethernet.TYPE, rdType, "IPV6");
			break;
		}

		default:

			int lineError = getLine();
			moveToNextFrameIndex();
			throw new NetworkanalyzerParseErrorException(lineError, "Unexpected value of the ethernet type field");
		}

		incIndex(Ethernet.TYPE);

		Field dest = new Field(Ethernet.DEST_ADDRESS, destMacAddress,
				destMacAddress.equals("FF FF FF FF FF FF") ? "broadcast" : destMacAddress.replace(" ", ":"));

		Field src = new Field(Ethernet.SRC_ADDRESS, srcMacAddress, srcMacAddress.replace(" ", ":"));

		ethernet.addField(Ethernet.SRC_ADDRESS.getKey(), src);
		ethernet.addField(Ethernet.DEST_ADDRESS.getKey(), dest);
		ethernet.addField(Ethernet.TYPE.getKey(), type);

		if (!isData) {
			ethernet.setIncluded(layer);
			layer.accept(this);

			return;
		}

		Entry<String, Integer> dataEntry = Ethernet.DATA.setValue(line.split(" ").length * 8);
		ethernet.addField(dataEntry.getKey(), new Field(dataEntry, line, line));
		throw new NetworkanalyzerParseWarningException(indexWarning, " IPV6 is not supported");
	}

	@Override
	public void visit(Ip ip) throws NetworkAnalyzerException {

		header = getHeader(60).trim();
		index = 0;

		String version = parseField(Ip.VERSION);

		if (!version.equals("4")) {
			int lineError = getLine();
			moveToNextFrameIndex();
			throw new NetworkanalyzerParseErrorException(lineError, "The IP Vesion is not compatible");
		}

		incIndex(Ip.VERSION);

		String ihl = parseField(Ip.IHL);

		int ihlDecoded = Integer.parseInt(ihl, 16);
		if (ihlDecoded < 5) {
			int lineError = getLine();
			moveToNextFrameIndex();
			throw new NetworkanalyzerParseErrorException(lineError, "The IP IHL is not compatible");
		}

		incIndex(Ip.IHL, true);

		String tos = parseField(Ip.TOS);
		incIndex(Ip.TOS);

		String totalLength = parseField(Ip.TOTAL_LENGTH);

		incIndex(Ip.TOTAL_LENGTH);

		String identification = parseField(Ip.IDENTIFICATION);
		incIndex(Ip.IDENTIFICATION);

		String fr = NetworkanalyzerTools.hexToBinEncoded(parseField(Ip.FRAGMENTS));

		while (fr.length() != 16)
			fr = "0".concat(fr);

		String r = fr.substring(0, 1);
		if (Integer.parseInt(r, 2) != 0) {
			int lineError = getLine();
			moveToNextFrameIndex();
			throw new NetworkanalyzerParseErrorException(lineError, "The TOS is not compatible");
		}
		String df = fr.substring(1, 2);
		String mf = fr.substring(2, 3);
		String fragmentOffset = fr.substring(3);
		if ((Integer.parseInt(mf, 2) == 1 && (Integer.parseInt(df, 2) == 1)
				|| Integer.parseInt(fragmentOffset, 2) == 1)) {
			int lineError = getLine();
			moveToNextFrameIndex();
			throw new NetworkanalyzerParseErrorException(lineError, "The TOS is not compatible");
		}

		incIndex(Ip.FRAGMENTS);

		String ttl = parseField(Ip.TTL);
		incIndex(Ip.TTL);

		String protocol = parseField(Ip.PROTOCOL);

		ILayerTransport layer = null;
		IField proto = null;
		int indexWarning = 0;
		boolean isData = false;
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
			isData = true;
			indexWarning = getLine();
			moveToNextFrameIndex();
			proto = new Field(Ip.PROTOCOL, protocol, "UNKNOW");
			break;
		}

		default:
			int lineError = getLine();
			moveToNextFrameIndex();
			throw new NetworkanalyzerParseErrorException(lineError, "Unexpected value of the ethernet type field");

		}

		incIndex(Ip.PROTOCOL);

		String headerChecksum = parseField(Ip.HEADER_CHECKSUM);
		incIndex(Ip.HEADER_CHECKSUM);

		String srcAddress = parseField(Ip.SRC_ADDRESS);
		incIndex(Ip.SRC_ADDRESS);

		String destAddress = parseField(Ip.DEST_ADDRESS);

		if (srcAddress.equals("FF FF FF FF")) {
			int lineError = getLine();
			moveToNextFrameIndex();
			throw new NetworkanalyzerParseErrorException(lineError,
					"The source IP address must not be a broadcast address");
		}

		if (srcAddress.equals(destAddress)) {
			int lineError = getLine();
			moveToNextFrameIndex();
			throw new NetworkanalyzerParseErrorException(lineError, "IP addresses are equal");
		}

		incIndex(Ip.DEST_ADDRESS);

		IField options = null;

		if (ihlDecoded > 5) {
			header = getHeader(((ihlDecoded - 5) * 12)).trim();
			options = OptionsBuilder.buildIpOptions(header);
		}

		ip.addField(Ip.DEST_ADDRESS.getKey(),
				new Field(Ip.DEST_ADDRESS, destAddress, NetworkanalyzerTools.decodeAddressIp(destAddress)));

		ip.addField(Ip.SRC_ADDRESS.getKey(),
				new Field(Ip.SRC_ADDRESS, srcAddress, NetworkanalyzerTools.decodeAddressIp(srcAddress)));

		ip.addField(Ip.PROTOCOL.getKey(), proto);

		ip.addField(Ip.VERSION.getKey(), new Field(Ip.VERSION, version, ip.getName()));

		ip.addField(Ip.IHL.getKey(), new Field(Ip.IHL, ihl, String.valueOf(ihlDecoded)));

		ip.addField(Ip.TOS.getKey(), new Field(Ip.TOS, tos, tos));

		ip.addField(Ip.TOTAL_LENGTH.getKey(),
				new Field(Ip.TOTAL_LENGTH, totalLength, NetworkanalyzerTools.toInteger(totalLength)));

		ip.addField(Ip.IDENTIFICATION.getKey(),
				new Field(Ip.IDENTIFICATION, identification, NetworkanalyzerTools.toInteger(identification)));

		Fields fragments = new Fields(Ip.FRAGMENTS.getKey());
		fragments.addField(new Field(Ip.R, r, r, true));
		fragments.addField(new Field(Ip.DF, df, df, true));
		fragments.addField(new Field(Ip.MF, mf, mf, true));
		fragments.addField(
				new Field(Ip.FRAGMENT_OFFSET, fragmentOffset, NetworkanalyzerTools.toInteger(fragmentOffset, 2), true));

		ip.addField(Ip.FRAGMENTS.getKey(), fragments);

		ip.addField(Ip.TTL.getKey(), new Field(Ip.TTL, ttl, NetworkanalyzerTools.toInteger(ttl)));
		ip.addField(Ip.HEADER_CHECKSUM.getKey(), new Field(Ip.HEADER_CHECKSUM, headerChecksum, headerChecksum));

		if (options != null) {
			Entry<String, Integer> os = Ip.OPTIONS.setValue(options.getLength());
			ip.addField(os.getKey(), options);
			incIndex(os);
		}

		if (!isData) {
			ip.setIncluded(layer);
			layer.accept(this);
			return;
		}

		Entry<String, Integer> dataEntry = Ip.DATA.setValue(line.split(" ").length * 8);
		ip.addField(dataEntry.getKey(), new Field(dataEntry, line, line));
		throw new NetworkanalyzerParseWarningException(indexWarning, "TCP protocol is not supported");
	}

	@Override
	public void visit(Udp udp) throws NetworkAnalyzerException {
		ILayerApplication layer = null;

		header = getHeader(24).trim();
		index = 0;

		String srcPort = parseField(Udp.SRC_PORT);
		incIndex(Udp.SRC_PORT);

		String destPort = parseField(Udp.SRC_PORT);

		int pDest = Integer.parseInt(destPort.replace(" ", ""), 16);
		int pSrc = Integer.parseInt(srcPort.replace(" ", ""), 16);

		boolean isDataEcapculed = false;
		switch (pSrc) {

		case Udp.DNS: {
			layer = new Dns();
			break;
		}

		default:
			if ((pDest == Udp.DHCP_1 && pSrc == Udp.DHCP_2) || (pDest == Udp.DHCP_2 && pSrc == Udp.DHCP_1)) {
				layer = new Dhcp();
				break;
			}

			isDataEcapculed = true;
		}

		incIndex(Udp.DEST_PORT);

		String length = parseField(Udp.LENGTH);
		incIndex(Udp.LENGTH);

		String checksum = parseField(Udp.CHECKSUM);
		incIndex(Udp.CHECKSUM);

		udp.addField(Udp.SRC_PORT.getKey(),
				new Field(Udp.SRC_PORT, srcPort, String.valueOf(Integer.parseInt(srcPort.replace(" ", ""), 16))));

		udp.addField(Udp.DEST_PORT.getKey(), new Field(Udp.DEST_PORT, destPort, String.valueOf(pDest)));

		udp.addField(Udp.LENGTH.getKey(),
				new Field(Udp.LENGTH, length, String.valueOf(Integer.parseInt(length.replace(" ", ""), 16))));

		udp.addField(Udp.CHECKSUM.getKey(),
				new Field(Udp.CHECKSUM, checksum, String.valueOf(Integer.parseInt(checksum.replace(" ", ""), 16))));
		if (isDataEcapculed) {
			String data = getHeader(line.length());

			Entry<String, Integer> dataEntry = Udp.DATA.setValue(data.split(" ").length * 8);
			incIndex(dataEntry);

			udp.addField(dataEntry.getKey(),
					new Field(dataEntry, data, data, String.format("%d bytes", dataEntry.getValue() / 8)));

			moveToNextFrameIndex();
			return;
		}

		udp.setIncluded(layer);
		layer.accept(this);
	}

	@Override
	public void visit(Dhcp dhcp) throws NetworkAnalyzerException {

		header = getHeader(720).trim();
		index = 0;

		// message type------------------------------------------
		String messageType = parseField(Dhcp.MESSAGE_TYPE);
		String messageTypeDecoded = NetworkanalyzerTools.toInteger(messageType);

		if (!messageTypeDecoded.equals("1") && !messageTypeDecoded.equals("2")) {
			int lineError = getLine();
			moveToNextFrameIndex();
			throw new NetworkanalyzerParseErrorException(lineError, "Unexpected value of the message type field");
		}
		incIndex(Dhcp.MESSAGE_TYPE);
		dhcp.addField(Dhcp.MESSAGE_TYPE.getKey(), new Field(Dhcp.MESSAGE_TYPE, messageType, messageTypeDecoded));

		// hardware type-----------------------------------------
		String hardwareType = parseField(Dhcp.HARDWARE_TYPE);
		incIndex(Dhcp.HARDWARE_TYPE);

		dhcp.addField(Dhcp.HARDWARE_TYPE.getKey(), new Field(Dhcp.HARDWARE_TYPE, hardwareType,
				HardwareDecoder.getType(Integer.parseInt(hardwareType.replace(" ", ""), 16)).getKey()));

		// hardware address length---------------------------------
		String hardwareAddressLenght = parseField(Dhcp.HARDWARE_ADDRESS_LENGTH);
		incIndex(Dhcp.HARDWARE_ADDRESS_LENGTH);

		dhcp.addField(Dhcp.HARDWARE_ADDRESS_LENGTH.getKey(), new Field(Dhcp.HARDWARE_ADDRESS_LENGTH,
				hardwareAddressLenght, NetworkanalyzerTools.toInteger(hardwareAddressLenght)));

		// hops ---------------------------------------------------
		String hops = parseField(Dhcp.HOPS);
		incIndex(Dhcp.HOPS);

		dhcp.addField(Dhcp.HOPS.getKey(), new Field(Dhcp.HOPS, hops, NetworkanalyzerTools.toInteger(hops)));
		// transaction ID
		String transactionId = parseField(Dhcp.TRANSACTION_ID);
		incIndex(Dhcp.TRANSACTION_ID);

		dhcp.addField(Dhcp.TRANSACTION_ID.getKey(),
				new Field(Dhcp.TRANSACTION_ID, transactionId, String.format("Ox%s", transactionId.replace(" ", ""))));

		// seconds elapsed
		String secondsElapsed = parseField(Dhcp.SECONDS_ELAPSED);
		incIndex(Dhcp.SECONDS_ELAPSED);

		dhcp.addField(Dhcp.SECONDS_ELAPSED.getKey(),
				new Field(Dhcp.SECONDS_ELAPSED, secondsElapsed, NetworkanalyzerTools.toInteger(secondsElapsed)));

		// Flags
		String fls = NetworkanalyzerTools.hexToBinEncoded(parseField(Dhcp.FLAGS));
		Fields flags = new Fields(Dhcp.FLAGS.getKey());
		char broadcast = fls.charAt(0);
		flags.addField(new Field(Dhcp.BROADCAST, String.valueOf(broadcast), broadcast == '1' ? "true" : "false", true));
		flags.addField(new Field(Dhcp.RESERVED, fls.substring(1), "0", true));
		dhcp.addField(Dhcp.FLAGS.getKey(), flags);

		incIndex(Dhcp.FLAGS);

		// Client Ip
		String clientIp = parseField(Dhcp.CLIENT_IP_ADDRESS);
		incIndex(Dhcp.CLIENT_IP_ADDRESS);
		dhcp.addField(Dhcp.CLIENT_IP_ADDRESS.getKey(),
				new Field(Dhcp.CLIENT_IP_ADDRESS, clientIp, NetworkanalyzerTools.decodeAddressIp(clientIp)));

		// Your ip
		String yourIp = parseField(Dhcp.YOUR_IP_ADDRESS);
		incIndex(Dhcp.YOUR_IP_ADDRESS);
		dhcp.addField(Dhcp.YOUR_IP_ADDRESS.getKey(),
				new Field(Dhcp.YOUR_IP_ADDRESS, yourIp, NetworkanalyzerTools.decodeAddressIp(yourIp)));

		String nextServerIp = parseField(Dhcp.NEXT_SERVER_IP_ADDRESS);
		incIndex(Dhcp.NEXT_SERVER_IP_ADDRESS);
		dhcp.addField(Dhcp.NEXT_SERVER_IP_ADDRESS.getKey(), new Field(Dhcp.NEXT_SERVER_IP_ADDRESS, nextServerIp,
				NetworkanalyzerTools.decodeAddressIp(nextServerIp)));

		String relayAgent = parseField(Dhcp.RELAY_AGENT_IP_ADDRESS);
		incIndex(Dhcp.RELAY_AGENT_IP_ADDRESS);
		dhcp.addField(Dhcp.RELAY_AGENT_IP_ADDRESS.getKey(),
				new Field(Dhcp.RELAY_AGENT_IP_ADDRESS, relayAgent, NetworkanalyzerTools.decodeAddressIp(relayAgent)));

		Entry<String, Integer> cma = Dhcp.CLIENT_MAC_ADDRESS
				.setValue(Integer.parseInt(NetworkanalyzerTools.toInteger(hardwareAddressLenght)) * 8);

		String clientMac = parseField(cma);
		incIndex(cma);

		dhcp.addField(cma.getKey(), new Field(cma, clientMac, clientMac.replace(" ", ":")));

		Entry<String, Integer> chpa = Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING.setValue(128 - cma.getValue());

		String padding = parseField(chpa);

		incIndex(chpa);

		dhcp.addField(chpa.getKey(), new Field(chpa, padding, NetworkanalyzerTools.toInteger(padding), ""));

		String serverHostName = parseField(Dhcp.SERVER_HOST_NAME);
		incIndex(Dhcp.SERVER_HOST_NAME);

		String result = serverHostName.replace(" ", "").replace("0", "").equals("") ? "not given"
				: NetworkanalyzerTools.toAscii(serverHostName);

		dhcp.addField(Dhcp.SERVER_HOST_NAME.getKey(), new Field(Dhcp.SERVER_HOST_NAME, serverHostName, result, ""));

		String bootFile = parseField(Dhcp.BOOT_FILE);

		result = bootFile.replace(" ", "").replace("0", "").equals("") ? "not given"
				: NetworkanalyzerTools.toAscii(bootFile);

		incIndex(Dhcp.BOOT_FILE);
		dhcp.addField(Dhcp.BOOT_FILE.getKey(), new Field(Dhcp.BOOT_FILE, bootFile, result, ""));

		String magicCookie = parseField(Dhcp.MAGIC_COOKIE);
		dhcp.addField(Dhcp.MAGIC_COOKIE.getKey(), new Field(Dhcp.MAGIC_COOKIE, magicCookie, dhcp.getName()));
		incIndex(Dhcp.MAGIC_COOKIE);

		try {
			header = getHeader(line.length()).trim();
		} catch (NetworkAnalyzerException e) {
			return;
		}

		IField opt = OptionsBuilder.buildDhcpOptions(header);
		Entry<String, Integer> os = Dhcp.OPTIONS.setValue(opt.getLength());

		dhcp.addField(os.getKey(), opt);
		incIndex(os);
		moveToNextFrameIndex();
	}

	@Override
	public void visit(Icmp icmp) throws NetworkAnalyzerException {
		header = getHeader(192).trim();
		index = 0;

		String type = parseField(Icmp.TYPE);
		int typeDecoded = Integer.parseInt(type, 16);

		if (typeDecoded != 0 && typeDecoded != 8) {
			int lineError = getLine();
			moveToNextFrameIndex();
			throw new NetworkanalyzerParseErrorException(lineError, "Unexpected value of the Icmp type field");
		}

		icmp.addField(Icmp.TYPE.getKey(), new Field(Icmp.TYPE, type, typeDecoded + ""));
		incIndex(Icmp.TYPE);

		String code = parseField(Icmp.CODE);
		icmp.addField(Icmp.CODE.getKey(), new Field(Icmp.CODE, code, Integer.parseInt(code, 16) + ""));
		incIndex(Icmp.CODE);

		String checksum = parseField(Icmp.CHECKSUM);

		icmp.addField(Icmp.CHECKSUM.getKey(),
				new Field(Icmp.CHECKSUM, checksum, String.valueOf(Integer.parseInt(checksum.replace(" ", ""), 16))));
		incIndex(Icmp.CHECKSUM);

		String id = parseField(Icmp.IDENTIFIER);
		icmp.addField(Icmp.IDENTIFIER.getKey(), new Field(Icmp.IDENTIFIER, id, id));
		incIndex(Icmp.IDENTIFIER);

		String sequenceNumber = parseField(Icmp.SEQUENCE_NUMBER);
		icmp.addField(Icmp.SEQUENCE_NUMBER.getKey(), new Field(Icmp.SEQUENCE_NUMBER, sequenceNumber,
				String.valueOf(Integer.parseInt(sequenceNumber.replace(" ", ""), 16))));
		incIndex(Icmp.SEQUENCE_NUMBER);

		String data = header.substring(index);

		Entry<String, Integer> dataEntry = Icmp.DATA.setValue(data.split(" ").length * 8);
		incIndex(dataEntry);

		icmp.addField(dataEntry.getKey(), new Field(dataEntry, data, dataEntry.getValue() / 8 + " bytes", ""));
		moveToNextFrameIndex();
	}

	@Override
	public void visit(Dns dns) throws NetworkAnalyzerException {

		header = getHeader(line.length()).trim();
		String[] data = header.split(" ");
		index = 0;

		String identifier = parseField(Dns.IDENTIFIER);
		incIndex(Dns.IDENTIFIER);

		String fls = NetworkanalyzerTools.hexToBinEncoded(parseField(Dns.FLAGS));

		String response = fls.substring(0, 1);
		String opcode = fls.substring(1, 5);
		String auth = fls.substring(5, 6);
		String trunc = fls.substring(6, 7);
		String recDes = fls.substring(7, 8);
		String recAva = fls.substring(8, 9);
		String Z = fls.substring(9, 10);
		String answ = fls.substring(10, 11);
		String nonAuth = fls.substring(11, 12);
		String reply = fls.substring(12);

		Fields flags = new Fields(Dns.FLAGS.getKey());

		flags.addField(new Field(Dns.RESPONSE, response, response, true));
		flags.addField(new Field(Dns.OPCODE, opcode, opcode, true));
		flags.addField(new Field(Dns.AUTHORITATIVE, auth, auth, true));
		flags.addField(new Field(Dns.TRUNCATED, trunc, trunc, true));
		flags.addField(new Field(Dns.RECURSION_DESIRED, recDes, recDes, true));
		flags.addField(new Field(Dns.RECURSION_AVAILABLE, recAva, recAva, true));
		flags.addField(new Field(Dns.Z, Z, Z, true));
		flags.addField(new Field(Dns.ANSWER_AUTHENTICATED, answ, answ, true));
		flags.addField(new Field(Dns.NON_AUTHENTICATED_DATA, nonAuth, nonAuth, true));
		flags.addField(new Field(Dns.REPLY_CODE, reply, reply, true));

		incIndex(Dns.FLAGS);

		String numberQst = parseField(Dns.QUESTIONS_NUMBER);
		incIndex(Dns.QUESTIONS_NUMBER);

		String numberAns = parseField(Dns.ANSWER_RRS_NUMBER);
		incIndex(Dns.ANSWER_RRS_NUMBER);

		String numberAuth = parseField(Dns.AUTHORITY_RRS_NUMBER);
		incIndex(Dns.AUTHORITY_RRS_NUMBER);

		String numberAdd = parseField(Dns.ADDITIONAL_RRS_NUMBER);
		incIndex(Dns.ADDITIONAL_RRS_NUMBER);

		String decodedNumberQst = NetworkanalyzerTools.toInteger(numberQst);
		String decodedNumberAns = NetworkanalyzerTools.toInteger(numberAns);
		String decodedNumberAuth = NetworkanalyzerTools.toInteger(numberAuth);
		String decodedNumberAdd = NetworkanalyzerTools.toInteger(numberAdd);

		int curr = 12;

		Fields questions = new Fields(Dns.QUESTIONS.getKey(), true);
		curr = addDnsVariableFields(curr, Dns.QUESTIONS, questions, data, decodedNumberQst, dns, true);

		Fields answers = new Fields(Dns.ANSWER.getKey(), true);
		curr = addDnsVariableFields(curr, Dns.ANSWER, answers, data, decodedNumberAns, dns, false);

		Fields authentifications = new Fields(Dns.AUTHORITY.getKey(), true);
		curr = addDnsVariableFields(curr, Dns.AUTHORITY, authentifications, data, decodedNumberAuth, dns, false);

		Fields addInfo = new Fields(Dns.ADDITIONAL_INFO.getKey(), true);
		curr = addDnsVariableFields(curr, Dns.ADDITIONAL_INFO, addInfo, data, decodedNumberAdd, dns, false);

		dns.addField(Dns.IDENTIFIER.getKey(), new Field(Dns.IDENTIFIER, identifier, identifier));

		dns.addField(Dns.FLAGS.getKey(), flags);

		dns.addField(Dns.QUESTIONS_NUMBER.getKey(), new Field(Dns.QUESTIONS_NUMBER, numberQst, decodedNumberQst));

		dns.addField(Dns.ANSWER_RRS_NUMBER.getKey(), new Field(Dns.ANSWER_RRS_NUMBER, numberAns, decodedNumberAns));

		dns.addField(Dns.AUTHORITY_RRS_NUMBER.getKey(),
				new Field(Dns.AUTHORITY_RRS_NUMBER, numberAuth, decodedNumberAuth));

		dns.addField(Dns.ADDITIONAL_RRS_NUMBER.getKey(),
				new Field(Dns.ADDITIONAL_RRS_NUMBER, numberAdd, decodedNumberAdd));

		moveToNextFrameIndex();

	}

	@Override
	public void visit(Arp arp) throws NetworkanalyzerParseErrorException {

		header = getHeader(84).trim();
		index = 0;

		String ht = parseField(Arp.HARDWARE_TYPE);
		Field htf = new Field(Arp.HARDWARE_TYPE, ht,
				HardwareDecoder.getType(Integer.parseInt(ht.replace(" ", ""), 16)).getKey());
		arp.addField(Arp.HARDWARE_TYPE.getKey(), htf);
		incIndex(Arp.HARDWARE_TYPE);

		String pt = parseField(Arp.PROTOCOL_TYPE);
		Field ptf = new Field(Arp.PROTOCOL_TYPE, pt, pt.equals("08 00") ? "IPV4" : "IPV6");
		arp.addField(Arp.PROTOCOL_TYPE.getKey(), ptf);
		incIndex(Arp.PROTOCOL_TYPE);

		String hs = parseField(Arp.HARDWARE_SIZE);
		int hsV = Integer.parseInt(hs.replace(" ", ""));
		Field hsf = new Field(Arp.HARDWARE_SIZE, hs, String.valueOf(hsV));
		arp.addField(Arp.HARDWARE_SIZE.getKey(), hsf);
		incIndex(Arp.HARDWARE_SIZE);

		String ps = parseField(Arp.PROTOCOL_SIZE);
		int psV = Integer.parseInt(ps.replace(" ", ""));
		Field psf = new Field(Arp.PROTOCOL_SIZE, ps, String.valueOf(psV));
		arp.addField(Arp.PROTOCOL_SIZE.getKey(), psf);
		incIndex(Arp.PROTOCOL_SIZE);

		String op = parseField(Arp.OPCODE);
		Field opf = new Field(Arp.OPCODE, op, ArpDecoder.getType(Integer.parseInt(op.replace(" ", ""), 16)).getKey());
		arp.addField(Arp.OPCODE.getKey(), opf);
		incIndex(Arp.OPCODE);

		Entry<String, Integer> smE = Arp.SOURCE_HARDWARE_ADDRESS.setValue(hsV * 8);
		String sm = parseField(smE);
		String smV = sm.replace(" ", ":");
		Field smf = new Field(smE, sm, smV);
		arp.addField(smE.getKey(), smf);
		incIndex(smE);

		Entry<String, Integer> spE = Arp.SOURCE_PROTOCOL_ADDRESS.setValue(psV * 8);
		String sp = parseField(spE);
		String spV;

		if (pt.equals(Ethernet.IPV4))
			spV = NetworkanalyzerTools.decodeAddressIp(sp);
		else {
			String[] data = sp.split(" ");
			spV = String.format("%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s", data[0], data[1], data[2], data[3], data[4],
					data[5], data[6], data[7]);
		}

		Field spf = new Field(spE, sp, spV);
		arp.addField(spE.getKey(), spf);

		incIndex(spE);

		Entry<String, Integer> dmE = Arp.DESTINATION_HARDWARE_ADDRESS.setValue(hsV * 8);
		String dm = parseField(dmE);
		String dmV = dm.replace(" ", ":");
		arp.addField(dmE.getKey(), new Field(dmE, dm, dmV));
		incIndex(dmE);

		Entry<String, Integer> dpE = Arp.DESTINATION_PROTOCOL_ADDRESS.setValue(psV * 8);
		String dp = parseField(dpE);
		String dpV;

		if (pt.equals(Ethernet.IPV4))
			dpV = NetworkanalyzerTools.decodeAddressIp(dp);
		else {
			String[] data = dp.split(" ");
			dpV = String.format("%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s", data[0], data[1], data[2], data[3], data[4],
					data[5], data[6], data[7]);
		}

		Field dpf = new Field(dpE, dp, dpV);
		arp.addField(dpE.getKey(), dpf);

		incIndex(dpE);

		moveToNextFrameIndex();
	}

	private int findName(String data[], int i) {

		while (isPointer(NetworkanalyzerTools.toBinaryQuartet(data[i].charAt(0))))
			i = Integer.parseInt(
					NetworkanalyzerTools.hexToBinEncoded(data[i].concat(data[i + 1]).replace(" ", "")).substring(3), 2);

		return i;
	}

	private int getDnsName(String data[], int curr, Fields fields) {
		boolean notJumped = true;
		int i = curr;

		StringBuilder sbV = new StringBuilder();
		StringBuilder sbN = new StringBuilder();

		while (!data[i].equals("00")) {

			if (isPointer(NetworkanalyzerTools.hexToBinEncoded(data[i]))) {

				if (notJumped) {
					sbV.append(String.format("%s %s ", data[i], data[i + 1]));
					notJumped = false;
					curr += 2;
				}

				i = findName(data, i);
			}

			else {
				int len = Integer.parseInt(data[i], 16);

				sbN.append(data[i]).append(" ");

				if (notJumped) {
					sbV.append(data[i]).append(" ");
					curr++;
				}

				i++;

				int k = i;
				for (int j = 0; j < len; j++) {

					if (notJumped) {
						sbV.append(data[k + j]).append(" ");
						curr++;
					}

					sbN.append(data[k + j]).append(" ");
					i++;
				}

			}
		}

		if (notJumped) {
			sbV.append("00");
			curr++;
		}

		String name = sbN.toString().strip();
		String value = sbV.toString().strip();
		String decoded = getDnsNameDecoded(name);

		Field f = new Field(new Entry<>("NAME", 0), value, decoded, name);
		fields.addField(f);

		return curr;
	}

	public String getDnsNameDecoded(String name) {

		StringBuilder sb = new StringBuilder();

		if (name.trim().equals(""))
			return "";

		String data[] = name.trim().split(" ");

		for (int i = 0; i < data.length;) {

			int len = Integer.parseInt(data[i++], 16);

			while (len != 0) {
				sb.append(NetworkanalyzerTools.toAscii(data[i++]));
				len--;
			}

			if (i != data.length - 1)
				sb.append(".");
		}

		return sb.toString().substring(0, sb.length() - 1);
	}

	private int parseDnsNames(int number, String data[], int curr, Fields container, boolean isQuestions) {

		for (int j = 0; j < number; j++) {
			StringBuilder sb = new StringBuilder();

			Fields item = new Fields(String.format("%s %d", "N° ", j), true);
			container.addField(item);

			curr = getDnsName(data, curr, item);

			String type = String.format("%s %s", data[curr], data[curr + 1]);
			curr += 2;

			String cls = String.format("%s %s", data[curr], data[curr + 1]);
			curr += 2;

			Field t = new Field(new Entry<String, Integer>(isQuestions ? "QTYPE" : "TYPE", 16), type,
					DnsDecoder.getType(Integer.parseInt(type.replace(" ", ""), 16)).getKey());

			Field c = new Field(new Entry<String, Integer>(isQuestions ? "QCLASS" : "CLASS", 16), cls,
					DnsDecoder.getClassName(Integer.parseInt(cls.replace(" ", ""), 16)));

			item.addField(t);
			item.addField(c);

			String rdataLength = "0";
			int numberData = 0;

			if (!isQuestions) {
				String ttl = String.format("%s %s %s %s", data[curr], data[curr + 1], data[curr + 2], data[curr + 3]);
				curr += 4;

				rdataLength = String.format("%s %s", data[curr], data[curr + 1]);
				curr += 2;

				Field tl = new Field(new Entry<String, Integer>("TTL", 32), ttl, NetworkanalyzerTools.toInteger(ttl));
				numberData = Integer.parseInt(NetworkanalyzerTools.toInteger(rdataLength));

				Field rData = new Field(new Entry<String, Integer>("RDATA LENGTH", 16), rdataLength, numberData + "");

				item.addField(tl);
				item.addField(rData);
			}

			if (!isQuestions) {

				String decType = "0x" + type.replace(" ", "").toLowerCase();
				String ipAddress;
				Field ip;

				if (decType.equals("0x0001")) {
					ipAddress = String.format("%s %s %s %s", data[curr], data[curr + 1], data[curr + 2],
							data[curr + 3]);
					curr += 4;
					ip = new Field(new Entry<String, Integer>("IP ADDRESS", 32), ipAddress,
							NetworkanalyzerTools.decodeAddressIp(ipAddress));
					item.addField(ip);
				}

				else if (decType.equals("0x001c")) {
					ipAddress = String.format("%s %s %s %s %s %s %s %s", data[curr], data[curr + 1], data[curr + 2],
							data[curr + 3], data[curr + 4], data[curr + 5], data[curr + 6], data[curr + 7]);

					String decIp = String.format("%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s", data[curr], data[curr + 1],
							data[curr + 2], data[curr + 3], data[curr + 4], data[curr + 5], data[curr + 6],
							data[curr + 7]);

					curr += 6;

					ip = new Field(new Entry<String, Integer>("IP ADDRESS", 32), ipAddress, decIp);
					item.addField(ip);

				}

				else if (decType.equals("0x0005") || decType.equals("0x0002") || decType.equals("0x000F"))
					curr = getDnsName(data, curr, item);

				else {

					int l = Integer.parseInt(rdataLength.replace(" ", ""), 16);

					sb = new StringBuilder();
					for (int k = 0; k < l; k++)
						sb.append(data[curr++]).append(" ");

					item.addField(new Field(new Entry<String, Integer>("Data", l), sb.toString(), "Uknown data"));
				}
			}
		}

		return curr;
	}

	private int addDnsVariableFields(int curr, Entry<String, Integer> entry, Fields fields, String[] data,
			String number, Dns dns, boolean isQst) throws NetworkanalyzerParseErrorException {

		try {
			int n = Integer.parseInt(number);

			if (n > 0) {
				int oldCurr = curr;
				curr = parseDnsNames(n, data, curr, fields, isQst);
				entry = entry.setValue((curr - oldCurr) * 8);
				incIndex(entry);
				dns.addField(entry.getKey(), fields);
			}
		} catch (IndexOutOfBoundsException e) {
			throw new NetworkanalyzerParseErrorException(getLine(), "The frame is not complete");
		}

		return curr;
	}

	private int getLine() {

		for (int i = 0; i < listIndex.size(); i++) {
			if (currentIndex < listIndex.get(i).get(0)) {
				if (i == 0)
					return 0;

				return listIndex.get(i - 1).get(1);
			}
		}

		return listIndex.get(listIndex.size() - 1).get(1);

	}

	private void moveToNextFrameIndex() {
		currentIndex = lastIndex;
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

	private String parseField(Entry<String, Integer> entry) throws NetworkanalyzerParseErrorException {

		try {
			int len = entry.getValue();
			int inc = 1;

			if (len % 8 == 0)
				inc = len / 4 + len / 8 - 1;

			return header.substring(index, index + inc);
		} catch (IndexOutOfBoundsException e) {
			throw new NetworkanalyzerParseErrorException(getLine(), "The frame is not complete");
		}
	}

	private void incIndex(Entry<String, Integer> entry, boolean end) {

		incIndex(entry);

		if (end) {
			currentIndex++;
			index++;
		}

	}

	private void incIndex(Entry<String, Integer> entry) {

		int len = entry.getValue();

		int inc = 1;

		if (len % 8 == 0)
			inc = len / 4 + len / 8;

		currentIndex += inc;
		index += inc;
	}

	private boolean isPointer(String b) {
		return b.startsWith("11");
	}

}