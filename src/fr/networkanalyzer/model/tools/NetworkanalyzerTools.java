package fr.networkanalyzer.model.tools;

public class NetworkanalyzerTools {

	public static String decodeAddressIp(String ipAddress) {
		String[] data = ipAddress.split(" ");
		return String.format("%d.%d.%d.%d", Integer.parseInt(data[0], 16), Integer.parseInt(data[1], 16),
				Integer.parseInt(data[2], 16), Integer.parseInt(data[3], 16));
	}

	public static String toAscii(String bytes) {
		StringBuilder sb = new StringBuilder();
		String bytesTab[] = bytes.split(" ");
	
		for (String s : bytesTab)
			sb.append((char) Integer.parseInt(s, 16));

		return sb.toString();
	}

	public static String toInteger(String value) {
		return String.valueOf(Integer.parseInt(value.replace(" ", ""), 16));
	}

	public static String toInteger(String value, int radix) {
		return String.valueOf(Integer.parseInt(value.replace(" ", ""), radix));
	}

	public static String toBinary(String value) {
		return Integer.toBinaryString(Integer.parseInt(value.replace(" ", ""),16));
	}
	
	public static String toBinaryQuartet(char value) {
		
		String r = toBinary(value+"");
		while(r.length() != 4)
			r= "0"+r;
		return r;
	}

}
