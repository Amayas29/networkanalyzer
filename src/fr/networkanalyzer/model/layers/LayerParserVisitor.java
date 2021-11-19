package fr.networkanalyzer.model.layers;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;

import fr.networkanalyzer.model.Field;
import fr.networkanalyzer.model.Fields;
import fr.networkanalyzer.model.IField;
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