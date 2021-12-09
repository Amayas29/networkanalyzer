package fr.networkanalyzer.model.decoder;

import java.util.HashMap;
import java.util.Map;

import fr.networkanalyzer.model.fields.Entry;

public class DnsDecoder extends Decoder {

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
	
	public static Entry<String,Integer> getType(int i){
		return Decoder.getType(i);
	}

}
