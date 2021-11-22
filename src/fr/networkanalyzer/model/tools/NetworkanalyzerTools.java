package fr.networkanalyzer.model.tools;

public class NetworkanalyzerTools {
	public static String decodeAddressIp(String ipAddress) {

		String[] data = ipAddress.split(" ");
		return String.format("%d.%d.%d.%d", Integer.parseInt(data[0], 16), Integer.parseInt(data[1], 16),
				Integer.parseInt(data[2], 16), Integer.parseInt(data[3], 16));
	}
}
