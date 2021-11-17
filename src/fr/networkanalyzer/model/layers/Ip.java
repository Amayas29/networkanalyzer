package fr.networkanalyzer.model.layers;

import java.io.BufferedReader;

public class Ip extends AbstractLayer implements LayerNetwork {

	public static final int ICMP = 1;
	public static final int UDP = 17;
	public static final int TCP = 6;

	public static final String VERSION = "version";
	public static final String IHL = "ihl";
	public static final String TOS = "tos";
	public static final String TOTAL_LENGTH = "totalLength";
	public static final String IDENTIFICATION = "identification";
	public static final String R = "r";
	public static final String DF = "df";
	public static final String MF = "mf";
	public static final String FRAGMENT_OFFSET = "fragmentOffset";
	public static final String TTL = "ttl";
	public static final String PROTOCOL = "protocol";
	public static final String HEADER_CHECKSUM = "headerChecksum";
	public static final String SRC_ADDRESS = "sourceAddress";
	public static final String DEST_ADDRESS = "destinationAddress";


	private LayerTransport included;

	@Override
	public Integer getTotalLength() {
		return Integer.parseInt(getField(TOTAL_LENGTH).getValueDecoded());
	}

	@Override
	public void parse(BufferedReader in) {

	}

	@Override
	public LayerTransport getIncluded() {
		return included;
	}
}