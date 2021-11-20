package fr.networkanalyzer.model.visitors;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;

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

public class LayerParserVisitor implements ILayerVisitor, Closeable {

	@SuppressWarnings("unused")
	private File file;

	public LayerParserVisitor(File file) {
		this.file = file;
	}

	@Override
	public void visit(Arp arp) {

	}

	@Override
	public void visit(Dhcp dhcp) {

		dhcp.addField(Dhcp.MESSAGE_TYPE.NAME, new Field(Dhcp.MESSAGE_TYPE, "01", "Boot Request"));
		dhcp.addField(Dhcp.HARDWARE_TYPE.NAME, new Field(Dhcp.HARDWARE_TYPE, "01", "Ethernet"));
		dhcp.addField(Dhcp.HARDWARE_ADDRESS_LENGTH.NAME, new Field(Dhcp.HARDWARE_ADDRESS_LENGTH, "06", "6"));
		dhcp.addField(Dhcp.HOPS.NAME, new Field(Dhcp.HOPS, "00", "0"));
		dhcp.addField(Dhcp.TRANSACTION_ID.NAME, new Field(Dhcp.TRANSACTION_ID, "d5 d1 5c 88", "Oxd5d15c88"));
		dhcp.addField(Dhcp.SECONDS_ELAPSED.NAME, new Field(Dhcp.SECONDS_ELAPSED, "00 00", "0"));

		Fields flags = new Fields(Dhcp.FLAGS.NAME);
		flags.addField(new Field(Dhcp.BROADCAST, "0", "0"));
		flags.addField(new Field(Dhcp.RESERVED, "000000000000000", "0"));
		dhcp.addField(Dhcp.FLAGS.NAME, flags);

		dhcp.addField(Dhcp.CLIENT_IP_ADDRESS.NAME, new Field(Dhcp.CLIENT_IP_ADDRESS, "00 00 00 00", "0.0.0.0"));
		dhcp.addField(Dhcp.YOUR_IP_ADDRESS.NAME, new Field(Dhcp.YOUR_IP_ADDRESS, "00 00 00 00", "0.0.0.0"));

		dhcp.addField(Dhcp.NEXT_SERVER_IP_ADDRESS.NAME,
				new Field(Dhcp.NEXT_SERVER_IP_ADDRESS, "00 00 00 00", "0.0.0.0"));

		dhcp.addField(Dhcp.RELAY_AGENT_IP_ADDRESS.NAME,
				new Field(Dhcp.RELAY_AGENT_IP_ADDRESS, "00 00 00 00", "0.0.0.0"));

		dhcp.addField(Dhcp.CLIENT_MAC_ADDRESS.NAME,
				new Field(Dhcp.CLIENT_MAC_ADDRESS, "32 20 a3 e2 d6 fe", "32:20:a3:e2:d6:fe"));

		dhcp.addField(Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING.NAME, new Field(Dhcp.CLIENT_HARDWARE_ADDRESS_PADDING,
				"00 00 00 00 00 00 00 00 00 00", "00 00 00 00 00 00 00 00 00 00"));

		dhcp.addField(Dhcp.SERVER_HOST_NAME.NAME, new Field(Dhcp.SERVER_HOST_NAME,
				"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
				"not given", false));

		dhcp.addField(Dhcp.BOOT_FILE.NAME, new Field(Dhcp.BOOT_FILE,
				"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
				"not given", false));

		dhcp.addField(Dhcp.MAGIC_COOKIE.NAME, new Field(Dhcp.MAGIC_COOKIE, "63 82 53 63", "dhcp"));
	}

	@Override
	public void visit(Dns dns) {

	}

	@Override
	public void visit(Ethernet ethernet) {

		IField type;
		ILayerNetwork layer = null;

		String read = "08 00";

		if (read.equals(Ethernet.IP)) {
			type = new Field(Ethernet.TYPE, read, "IPV4");
			layer = new Ip();
		}

		else if (read.equals(Ethernet.ARP)) {
			type = new Field(Ethernet.TYPE, read, "ARP");
			layer = new Arp();
		}

		else
			return;
		Field src = new Field(Ethernet.SRC_ADDRESS, "EE EE EE EE EE EE", "23:23:23:23:23:23");
		Field dest = new Field(Ethernet.DEST_ADDRESS, "FF FF FF FF FF FF", "broadcast");

		ethernet.addField(Ethernet.SRC_ADDRESS.NAME, src);
		ethernet.addField(Ethernet.DEST_ADDRESS.NAME, dest);

		ethernet.addField(Ethernet.TYPE.NAME, type);
		layer.accept(this);
		ethernet.setIncluded(layer);

	}

	@Override
	public void visit(Http http) {

	}

	@Override
	public void visit(Icmp icmp) {

	}

	@Override
	public void visit(Imap imap) {

	}

	@Override
	public void visit(Ip ip) {
		ip.addField(Ip.DEST_ADDRESS.NAME, new Field(Ip.DEST_ADDRESS, "11 11 11 11", "17.17.17.17"));
		ip.addField(Ip.SRC_ADDRESS.NAME, new Field(Ip.SRC_ADDRESS, "22 22 22 22", "18.18.18.18"));
		ip.addField(Ip.PROTOCOL.NAME, new Field(Ip.PROTOCOL, "33", "Icmp"));

		ip.addField(Ip.VERSION.NAME, new Field(Ip.VERSION, "4", "Ipv4"));
		ip.addField(Ip.IHL.NAME, new Field(Ip.IHL, "5", "15"));
		ip.addField(Ip.TOS.NAME, new Field(Ip.TOS, "66", "0"));
		ip.addField(Ip.TOTAL_LENGTH.NAME, new Field(Ip.TOTAL_LENGTH, "77 77", "155"));

		ip.addField(Ip.IDENTIFICATION.NAME, new Field(Ip.IDENTIFICATION, "88 88", "0"));

		Fields fragments = new Fields(Ip.FRAGMENTS.NAME);
		fragments.addField(new Field(Ip.R, "0", "0"));
		fragments.addField(new Field(Ip.DF, "0", "0"));
		fragments.addField(new Field(Ip.MF, "0", "0"));
		fragments.addField(new Field(Ip.FRAGMENT_OFFSET, "0000000000000", "0"));

		ip.addField(Ip.FRAGMENTS.NAME, fragments);

		ip.addField(Ip.TTL.NAME, new Field(Ip.TTL, "99 99", "1"));
		ip.addField(Ip.HEADER_CHECKSUM.NAME, new Field(Ip.HEADER_CHECKSUM, "AA AA", "0"));

		ILayerTransport udp = new Udp();
		udp.accept(this);
		ip.setIncluded(udp);
	}

	@Override
	public void visit(Tcp tcp) {

	}

	@Override
	public void visit(Udp udp) {
		udp.addField(Udp.SRC_PORT.NAME, new Field(Udp.SRC_PORT, "00 80", "80"));
		udp.addField(Udp.DEST_PORT.NAME, new Field(Udp.DEST_PORT, "00 80", "80"));
		udp.addField(Udp.LENGTH.NAME, new Field(Udp.LENGTH, "00 80", "80"));
		udp.addField(Udp.CHECKSUM.NAME, new Field(Udp.CHECKSUM, "00 80", "80"));

		ILayerApplication dhcp = new Dhcp();
		dhcp.accept(this);
		udp.setIncluded(dhcp);
	}

	@Override
	public void close() throws IOException {

	}

}