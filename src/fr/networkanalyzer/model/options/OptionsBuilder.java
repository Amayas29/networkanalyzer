package fr.networkanalyzer.model.options;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.Field;
import fr.networkanalyzer.model.fields.Fields;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.protocols.Dhcp;
import fr.networkanalyzer.model.layers.protocols.Ip;
import fr.networkanalyzer.model.tools.NetworkanalyzerTools;

public class OptionsBuilder {

	public static IField buildIpOptions(String header) throws NetworkAnalyzerException {

		Fields options = new Fields(Ip.OPTIONS.getKey(), true);

		String data[] = header.trim().split(" ");
		for (int i = 0; i < data.length;) {

			String type = data[i++];
			int typeDecoded = Integer.parseInt(type, 16);

			Entry<String, Integer> typeEnty = IpOptions.getEntryByCode(typeDecoded);
			Entry<String, Integer> t = new Entry<>("Option " + typeEnty.getKey(), 8);
			if (typeDecoded == 68)
				continue;

			if (typeDecoded == 1 || typeDecoded == 0) {
				options.addField(new Field(t, type, String.valueOf(typeDecoded)));
				continue;
			}

			Fields option = new Fields(String.format("%s %d", typeEnty.getKey(), typeDecoded), true);
			option.addField(new Field(new Entry<>("Type", 8), type, String.valueOf(typeDecoded)));

			String len = data[i++];
			int lenDecoded = Integer.parseInt(len, 16);
			option.addField(new Field(new Entry<>("Length", 8), len, String.valueOf(lenDecoded)));

			if (typeDecoded == 7) {
				String ptr = data[i++];
				option.addField(new Field(new Entry<>("Pointer", 8), ptr, String.valueOf(Integer.parseInt(ptr, 16))));
				lenDecoded -= 1;
			}

			lenDecoded -= 2;
			Fields fieldsAdresses = new Fields("Address", true);

			for (int j = 3, k = 1; j < lenDecoded; j += 4, k += 1) {
				String ips = String.format("%s %s %s %s", data[j], data[j + 1], data[j + 2], data[j + 3]);
				fieldsAdresses.addField(
						new Field(new Entry<>("address " + k, 32), ips, NetworkanalyzerTools.decodeAddressIp(ips)));
				i += 4;

			}

			option.addField(fieldsAdresses);
			options.addField(option);

		}

		return options;
	}

	public static IField buildDhcpOptions(String header) throws NetworkAnalyzerException {
		Fields options = new Fields(Dhcp.OPTIONS.getKey(), true);

		String data[] = header.split(" ");

		for (int i = 0; i < data.length;) {
			DhcpOption dOption = DhcpOption.getOptionByCode(data[i]);

			if (dOption == DhcpOption.PAD) {
				options.addField(new Field(new Entry<>(dOption.getName(), 16), data[i++], "0"));
				continue;
			}

			if (dOption == DhcpOption.END) {
				options.addField(new Field(new Entry<>(dOption.getName(), 16), data[i++], "255"));
				continue;
			}

			Fields option = new Fields(dOption.getName(), true);
			String name = data[i++];
			String length = data[i++];
			int l = Integer.parseInt(length, 16);
			Field type = new Field(new Entry<>("Type", 16), name, dOption.getCode() + "");

			Field len = new Field(new Entry<>("Length", 16), length, l + "");
			option.addField(type);
			option.addField(len);

			if (dOption.getCode() == 61) {
				String hardwareType = data[i];
				i++;
				option.addField(new Field(Dhcp.HARDWARE_TYPE, hardwareType, hardwareType));

				String clientMac = String.format("%s %s %s %s %s %s", data[i], data[i + 1], data[i + 2], data[i + 3],
						data[i + 4], data[i + 5]);

				option.addField(new Field(Dhcp.CLIENT_MAC_ADDRESS, clientMac, clientMac.replace(' ', ':')));
				i += 6;

				options.addField(option);
				continue;
			}

			if (dOption.getType() == DhcpOptionType.IP_OPTION) {
				Fields valuesOption;
				valuesOption = new Fields("Address", true);

				for (int j = 0; j < l; j += 4) {
					String ips = String.format("%s %s %s %s", data[j + i], data[j + 1 + i], data[j + 2 + i],
							data[j + 3 + i]);
					valuesOption.addField(new Field(new Entry<>(dOption.getName(), 32), ips,
							NetworkanalyzerTools.decodeAddressIp(ips)));
					i += 4;
				}

				option.addField(valuesOption);
				options.addField(option);
				continue;
			}

			if (dOption.getType() == DhcpOptionType.ASCII_OPTION) {
				StringBuilder sb = new StringBuilder();
				int j;

				for (j = 0; j < l; j++)
					sb.append(data[i + j]).append(" ");

				i += j;
				option.addField(new Field(new Entry<>(dOption.getName(), l), sb.toString(),
						NetworkanalyzerTools.toAscii(sb.toString())));
				options.addField(option);
				continue;
			}

			if (dOption.getType() == DhcpOptionType.HEXA_OPTION) {
				StringBuilder sb = new StringBuilder();

				int j;
				for (j = 0; j < l; j++)
					sb.append(data[i + j]).append(" ");

				i += j;

				Entry<String, Integer> e;
				try {
					e = DhcpOption.getEntryTypeDhcp(Integer.parseInt(sb.toString().replace(" ", ""), 16));
					e = e.setValue(l);
				} catch (Exception x) {
					e = new Entry<>(dOption.getName(), l);
				}

				option.addField(new Field(e, sb.toString(), e.getKey()));
				options.addField(option);

				continue;

			}

			if (dOption.getType() == DhcpOptionType.INT_OPTION) {
				StringBuilder sb = new StringBuilder();

				int j = 0;
				for (; j < l; j++) {
					sb.append(data[i + j]).append(" ");

				}

				i += j;

				option.addField(new Field(new Entry<>(dOption.getName(), l), sb.toString(),
						NetworkanalyzerTools.toInteger(sb.toString())));

				options.addField(option);
				continue;
			}

			if (dOption.getType() == DhcpOptionType.LISTE_OPTION) {
				int j;
				for (j = 0; j < l; j++) {
					option.addField(new Field(new Entry<>(dOption.getName(), 8), data[i + j],
							NetworkanalyzerTools.toInteger(data[i + j])));
				}

				i += j;

				options.addField(option);
				continue;

			}
			if (dOption.getType() == DhcpOptionType.TIME_OPTION) {
				StringBuilder sb = new StringBuilder();

				int j = 0;
				for (; j < l; j++)
					sb.append(data[i + j]).append(" ");

				i += j;

				int sec = Integer.parseInt(sb.toString().replace(" ", ""), 16);
				int min = sec / 60;
				sec %= 60;
				int heure = min / 60;
				min %= 60;

				option.addField(new Field(new Entry<>(dOption.getName(), l), sb.toString(),
						heure + " h " + min + " m " + sec + " s"));
				options.addField(option);
				continue;

			}

		}

		return options;

	}
}
