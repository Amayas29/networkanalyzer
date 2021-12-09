package fr.networkanalyzer.model.decodes;

import java.util.HashMap;
import java.util.Map;

import fr.networkanalyzer.model.fields.Entry;

public abstract class Decode {
	private static Map<Integer, String> types  = new HashMap<>();
	
	public static Entry<String, Integer> getType(int code) {

		String type = types.get(code);

		if (type == null)
			type = types.get(-1);

		return new Entry<String, Integer>(type, 16);
	}
	
	public static void put(Integer i ,String s) {
		types.put(i, s);
	}
	
}
