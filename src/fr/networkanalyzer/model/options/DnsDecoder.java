package fr.networkanalyzer.model.options;

import java.util.HashMap;
import java.util.Map;

public class DnsDecoder {

	private static Map<Integer, String> classes;
	private static Map<Integer, String> types;

	static {
		classes = new HashMap<>();
		types = new HashMap<>();

		classes.put(0, "Reserved");
		classes.put(1, "Internet");
		classes.put(3, "Chaos");
		classes.put(4, "Hesiod");
		classes.put(254, "QCLASS NONE");
		classes.put(255, "QCLASS ANY");

		types.put(1, "A");
		types.put(28, "AAAA");
		types.put(5, "CNAME");
		types.put(2, "NS");
		types.put(15, "MX");
	}

	public static String getClassName(int code) {
		String name = classes.get(code);

		if (name == null)
			return "UKNOWN";

		return name;
	}

	public static String getTypeName(int code) {
		String name = types.get(code);

		if (name == null)
			return "UKNOWN";

		return name;
	}
}
