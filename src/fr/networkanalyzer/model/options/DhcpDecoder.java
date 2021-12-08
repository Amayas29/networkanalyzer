package fr.networkanalyzer.model.options;

import java.util.HashMap;
import java.util.Map;

import fr.networkanalyzer.model.fields.Entry;

public class DhcpDecoder {

	private static Map<Integer, String> types;

	static {
		types = new HashMap<>();

		types.put(1, "Discover");
		types.put(2, "Offer");
		types.put(3, "Request");
		types.put(4, "Decline");
		types.put(5, "ACK");
		types.put(6, "NAK");
		types.put(7, "Release");
		types.put(8, "Inform");
		types.put(9, "Force Renew");
		types.put(10, "Lease query");
		types.put(-1, "Unknow");

	}

	public static Entry<String, Integer> getType(int code) {

		String type = types.get(code);

		if (type == null)
			type = types.get(-1);

		return new Entry<String, Integer>(type, 16);
	}
}
