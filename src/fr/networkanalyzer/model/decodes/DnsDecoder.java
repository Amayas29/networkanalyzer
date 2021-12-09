package fr.networkanalyzer.model.decodes;

import java.util.HashMap;
import java.util.Map;

public class DnsDecoder extends Decode {

	private static Map<Integer, String> classes;

	static {
		classes = new HashMap<>();

		classes.put(0, "Reserved");
		classes.put(1, "Internet");
		classes.put(3, "Chaos");
		classes.put(4, "Hesiod");
		classes.put(254, "QCLASS NONE");
		classes.put(255, "QCLASS ANY");

		put(1, "A");
		put(28, "AAAA");
		put(5, "CNAME");
		put(2, "NS");
		put(15, "MX");
	}

	public static String getClassName(int code) {
		String name = classes.get(code);

		if (name == null)
			return "UKNOWN";

		return name;
	}

}
