package fr.networkanalyzer.model.layers;

import java.io.BufferedReader;

public class Udp extends AbstractLayer implements LayerTransport {

	public static final int DNS = 53;
	public static final int DHCP = 67;
	
	public static final String SRC_PORT = "srcPort";
	public static final String DEST_PORT = "destPort";
	public static final String LENGTH = "length";
	public static final String CHECKSUM = "checksum";
	
	
	private LayerApplication included;

	@Override
	public void parse(BufferedReader in) {

	}

	@Override
	public LayerApplication getIncluded() {
		return included;
	}
}