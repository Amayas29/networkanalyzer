package fr.networkanalyzer.model.visitors;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
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
import fr.networkanalyzer.model.layers.protocols.Dhcp;
import fr.networkanalyzer.model.layers.protocols.Dns;
import fr.networkanalyzer.model.layers.protocols.Ethernet;
import fr.networkanalyzer.model.layers.protocols.Ip;
import fr.networkanalyzer.model.layers.protocols.Udp;
import fr.networkanalyzer.model.options.DnsDecoder;
import fr.networkanalyzer.model.options.OptionsBuilder;
import fr.networkanalyzer.model.tools.NetworkanalyzerTools;
import fr.networkanalyzer.model.tools.ParsingTools;

public class LayerParserVisitor implements ILayerVisitor {

	private String line;
	private List<Entry<Integer, Integer>> listIndex;
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

		index = 0;
		header = null;

		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < data.length; i++) {
			if (ParsingTools.isPattern(data[i])) {
				listIndex.add(new Entry<>(ParsingTools.getIndexPattern(data[i]), ParsingTools.getLinePattern(data[i])));
				continue;
			}

			sb.append(data[i].concat(" "));
		}

		Collections.sort(listIndex, new Comparator<Entry<Integer, Integer>>() {

			@Override
			public int compare(Entry<Integer, Integer> o1, Entry<Integer, Integer> o2) {
				return o1.getKey() - o2.getKey();
			}
		});

		this.line = sb.toString().trim();
	}

	@Override
	public void visit(Ethernet ethernet) throws NetworkAnalyzerException {

		System.out.println("Ethernet debut : " + currentIndex + " -> " + getLine());
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
//			layer = new Arp();
//			type = new Field(Ethernet.TYPE, rdType, layer.getName());
//			break;

			throw new NetworkanalyzerParseErrorException(getLine(), "ARP protocol is not supported");
		}

		default:
			throw new NetworkanalyzerParseErrorException(getLine(), "Unexpected value of the ethernet type field");
		}

		incIndex(Ethernet.TYPE);

		Field dest = new Field(Ethernet.DEST_ADDRESS, destMacAddress,
				destMacAddress.equals("FF FF FF FF FF FF") ? "broadcast" : destMacAddress.replace(" ", ":"));

		Field src = new Field(Ethernet.SRC_ADDRESS, srcMacAddress, srcMacAddress.replace(" ", ":"));

		ethernet.addField(Ethernet.SRC_ADDRESS.getKey(), src);
		ethernet.addField(Ethernet.DEST_ADDRESS.getKey(), dest);
		ethernet.addField(Ethernet.TYPE.getKey(), type);

		System.out.println("Ethernet apres : " + currentIndex + " -> " + getLine());
		layer.accept(this);
		ethernet.setIncluded(layer);
	}

	@Override
	public void visit(Ip ip) throws NetworkAnalyzerException {

		System.out.println("Ip debut : " + currentIndex + " -> " + getLine());
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

		String fr = NetworkanalyzerTools.hexToBinEncoded(parseField(Ip.FRAGMENTS));

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

			throw new NetworkanalyzerParseErrorException(getLine(), "ICMP protocol is not supported");

		}
		case Ip.UDP: {
			layer = new Udp();
			proto = new Field(Ip.PROTOCOL, protocol, layer.getName());
			break;
		}

		case Ip.TCP: {

			throw new NetworkanalyzerParseErrorException(getLine(), "TCP protocol is not supported");
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

		if (options != null)
			ip.addField(Ip.OPTIONS.getKey(), options);

		System.out.println("Ip apres : " + currentIndex + " -> " + getLine());
		layer.accept(this);
		ip.setIncluded(layer);
	}

	@Override
	public void visit(Udp udp) throws NetworkAnalyzerException {

		System.out.println("Udp debut : " + currentIndex + " -> " + getLine());
		ILayerApplication layer;

		header = getHeader(24).trim();
		index = 0;

		String srcPort = parseField(Udp.SRC_PORT);
		incIndex(Udp.SRC_PORT);

		String destPort = parseField(Udp.SRC_PORT);

		int pDest = Integer.parseInt(destPort.replace(" ", ""), 16);
		int pSrc = Integer.parseInt(srcPort.replace(" ", ""), 16);

//		if (pDest == pSrc && pSrc < 1024)
//			throw new NetworkanalyzerParseErrorException(getLine(), "Unexpected value of the Udp port fields");

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

			throw new NetworkanalyzerParseErrorException(getLine(),
					"Unexpected value of the Udp port destination field");
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

		System.out.println("udp apres : " + currentIndex + " -> " + getLine());
		layer.accept(this);
		udp.setIncluded(layer);
	}

	@Override
	public void visit(Dhcp dhcp) throws NetworkAnalyzerException {

		System.out.println("dhcp debut : " + currentIndex + " -> " + getLine());
		header = getHeader(720).trim();
		index = 0;

		// message type------------------------------------------
		String messageType = parseField(Dhcp.MESSAGE_TYPE);
		String messageTypeDecoded = NetworkanalyzerTools.toInteger(messageType);

		if (!messageTypeDecoded.equals("1") && !messageTypeDecoded.equals("2"))
			throw new NetworkanalyzerParseErrorException(getLine(), "Unexpected value of the message type field");

		incIndex(Dhcp.MESSAGE_TYPE);
		dhcp.addField(Dhcp.MESSAGE_TYPE.getKey(), new Field(Dhcp.MESSAGE_TYPE, messageType, messageTypeDecoded));

		// hardware type-----------------------------------------
		String hardwareType = parseField(Dhcp.HARDWARE_TYPE);
		incIndex(Dhcp.HARDWARE_TYPE);

		dhcp.addField(Dhcp.HARDWARE_TYPE.getKey(),
				new Field(Dhcp.HARDWARE_TYPE, hardwareType, NetworkanalyzerTools.toInteger(hardwareType)));

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
				new Field(Dhcp.TRANSACTION_ID, transactionId, NetworkanalyzerTools.toInteger(transactionId)));

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
		incIndex(Dhcp.CLIENT_MAC_ADDRESS);

		dhcp.addField(Dhcp.CLIENT_MAC_ADDRESS.getKey(),
				new Field(Dhcp.CLIENT_MAC_ADDRESS, clientMac, clientMac.replace(" ", ":")));

		Entry<String, Integer> chpa = Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING.setValue(128 - cma.getValue());

		String padding = parseField(chpa);

		incIndex(chpa);

		dhcp.addField(Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING.getKey(),
				new Field(Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING, padding, NetworkanalyzerTools.toInteger(padding), ""));

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

		dhcp.addField(Dhcp.OPTIONS.getKey(), opt);
		incIndex(Dhcp.OPTIONS);
		System.out.println("dhcp apres : " + currentIndex + " -> " + getLine());
	}

	private int findName(String data[], int i) {

		while (isPointer(NetworkanalyzerTools.toBinaryQuartet(data[i].charAt(0))))
			i = Integer.parseInt(
					NetworkanalyzerTools.hexToBinEncoded(data[i].concat(data[i + 1]).replace(" ", "")).substring(3), 2);

		return i;
	}

	private int getDnsName(String data[], int curr, Fields fields) {
		boolean jump = true;
		int i = curr;

		StringBuilder sbV = new StringBuilder();
		StringBuilder sbN = new StringBuilder();

		while (!data[i].equals("00")) {

			if (isPointer(NetworkanalyzerTools.hexToBinEncoded(data[i]))) {

				if (jump) {
					sbV.append(String.format("%s %s ", data[i], data[i + 1]));
					jump = false;
					curr += 2;
				}

				i = findName(data, i);
			}

			else {
				int len = Integer.parseInt(data[i], 16);

				sbN.append(data[i]).append(" ");

				if (jump) {
					sbV.append(data[i]).append(" ");
					curr++;
				}

				i++;

				int k = i;
				for (int j = 0; j < len; j++) {

					if (jump) {
						sbV.append(data[k + j]).append(" ");
						curr++;
					}

					sbN.append(data[k + j]).append(" ");
					i++;
				}

			}
		}

		if (jump) {
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
					DnsDecoder.getTypeName(Integer.parseInt(type.replace(" ", ""), 16)));

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

	@Override
	public void visit(Dns dns) throws NetworkAnalyzerException {

		System.out.println("dns debut : " + currentIndex + " -> " + getLine());
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

		System.out.println("dns apres : " + currentIndex + " -> " + getLine());
	}

	private int addDnsVariableFields(int curr, Entry<String, Integer> entry, Fields fields, String[] data,
			String number, Dns dns, boolean isQst) {

		int n = Integer.parseInt(number);

		if (n > 0) {
			int oldCurr = curr;
			curr = parseDnsNames(n, data, curr, fields, isQst);
			entry = entry.setValue((curr - oldCurr) * 8);
			incIndex(entry);
			dns.addField(entry.getKey(), fields);
		}

		return curr;
	}

	private int getLine() {

		for (int i = 0; i < listIndex.size(); i++) {
			if (currentIndex < listIndex.get(i).getKey()) {
				if (i == 0)
					return 0;

				return listIndex.get(i - 1).getValue();
			}
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

	private String parseField(Entry<String, Integer> entry) {

		int len = entry.getValue();
		int inc = 1;

		if (len % 8 == 0)
			inc = len / 4 + len / 8 - 1;

		return header.substring(index, index + inc);
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