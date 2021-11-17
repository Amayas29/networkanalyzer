package fr.networkanalyzer.model.layers;

import java.io.BufferedReader;

public class Tcp extends AbstractLayer implements LayerTransport {

	public static final int HTTP = 80;
	public static final int IMAP = 143;

	private LayerApplication included;

	public static final String SRC_PORT = "srcPort";
	public static final String DEST_PORT = "destPort";
	public static final String SEQUENCE_NUMBER = "sequenceNumber";
	public static final String ACKNOWLEDGMENT_NUMBER = "ackNumber";
	public static final String THL = "thl";
	public static final String RESERVED = "reserved";
	public static final String URG = "urg";
	public static final String ACK = "ack";
	public static final String PSH = "psh";
	public static final String RST = "rst";
	public static final String SYN = "syn";
	public static final String FIN = "fin";
	public static final String WINDOW = "window";
	public static final String CHECKSUM = "checksum";
	public static final String URGENT_POINTER = "urgentPointer";
	

	
	@Override
	public void parse(BufferedReader in) {

	}

	@Override
	public LayerApplication getIncluded() {
		return included;
	}
}