package fr.networkanalyzer.model.decodes;

import java.util.Map;

public class DhcpDecoder extends Decode {

	static {

		put(1, "Discover");
		put(2, "Offer");
		put(3, "Request");
		put(4, "Decline");
		put(5, "ACK");
		put(6, "NAK");
		put(7, "Release");
		put(8, "Inform");
		put(9, "Force Renew");
		put(10, "Lease query");
		put(-1, "Unknow");

	}

}