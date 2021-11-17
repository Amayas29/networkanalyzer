package fr.networkanalyzer.model.layers;

import java.io.BufferedReader;
import java.io.File;

import fr.networkanalyzer.model.Field;

public class Ethernet extends AbstractLayer implements LayerDataLink {

	public static final int ARP = 0x0806;
	public static final int IP = 0x0800;

	public static final String DEST_ADDRESS = "destinationAddress";
	public static final String SRC_ADDRESS = "sourceAddress";
	public static final String TYPE = "type";

	private LayerNetwork included;

	@Override
	public Integer getTotalLength() {
		return 14 + included.getTotalLength();
	}

	@Override
	public void parse(BufferedReader in) {
		included = new Ip();
		included.addField(Ip.DEST_ADDRESS, new Field("dest", "0", "10.10.10.10", 0));
		included.addField(Ip.SRC_ADDRESS, new Field("srs", "0", "10.10.10.10", 0));
		included.addField(Ip.TOTAL_LENGTH, new Field("tl", "", "100", 0));
		included.addField(Ip.PROTOCOL, new Field("", "", "Icmp", 0));
	}

	@Override
	public LayerNetwork getIncluded() {
		return included;
	}
}