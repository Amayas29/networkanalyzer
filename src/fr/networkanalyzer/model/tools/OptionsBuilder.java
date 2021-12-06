package fr.networkanalyzer.model.tools;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.Field;
import fr.networkanalyzer.model.fields.Fields;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.protocols.Dhcp;
import fr.networkanalyzer.model.layers.protocols.Ip;

public class OptionsBuilder {

	public static IField buildIpOptions(String header) throws NetworkAnalyzerException {

		Fields options = new Fields(Ip.OPTIONS.getName());

		String data[] = header.trim().split(" ");
		for (int i = 0; i < data.length;) {

			String type = data[i++];
			System.out.println("le type " + type);
			int typeDecoded = Integer.parseInt(type, 16);
			Entry typeEnty = IpOptions.getEntryByCode(typeDecoded);

			if (typeDecoded == 68)
				continue;
			if (typeDecoded == 1 || typeDecoded == 0) {
				options.addField(new Field(typeEnty, type, String.valueOf(typeDecoded)));
				continue;
			}

			Fields option = new Fields(String.valueOf(typeDecoded));
			option.addField(new Field(typeEnty, type, String.valueOf(typeDecoded)));

			String len = data[i++];
			int lenDecoded = Integer.parseInt(len, 16);
			option.addField(new Field(new Entry("Length", 8), len, String.valueOf(lenDecoded)));

			if (typeDecoded == 7) {
				String ptr = data[i++];
				option.addField(new Field(typeEnty, ptr, String.valueOf(Integer.parseInt(ptr, 16))));
				lenDecoded -= 1;
			}

			lenDecoded -= 2;
			Fields fieldsAdresses = null;
			for (int j = 3; j < lenDecoded; j += 4) {
				fieldsAdresses = new Fields(Ip.IPS_ADRESSES.getName());
				String ips = String.format("%s %s %s %s", data[j], data[j + 1], data[j + 2], data[j + 3]);
				fieldsAdresses
						.addField(new Field(new Entry("address", 32), ips, NetworkanalyzerTools.decodeAddressIp(ips)));
				i += 4;
			}
			option.addField(fieldsAdresses);
			options.addField(option);

		}

		return options;
	}

	public static IField buildDhcpOptions(String header) throws NetworkAnalyzerException {
		Fields options = new Fields(Dhcp.OPTIONS.getName());

		String data[] = header.split(" ");

		for (int i = 0; i < data.length;) {
			DhcpOption dOption = DhcpOption.getOptionByCode(data[i]);
			if (dOption == DhcpOption.PAD) {
				options.addField(new Field(new Entry(dOption.getName(), 0), data[i++], "0"));
				continue;
			}
			if (dOption == DhcpOption.END) {
				options.addField(new Field(new Entry(dOption.getName(), 255), data[i++], "255"));
				continue;
			}

			if (dOption.hasLength()) {
				Fields option = new Fields(dOption.getName());
				String name = data[i++];
				String length = data[i++];
				int l = Integer.parseInt(length, 16);
				Field type = new Field(new Entry("Type", 0), name, dOption.getCode() + "");

				Field len = new Field(new Entry("Length", 0), length, l + "");
				option.addField(type);
				option.addField(len);

				if (dOption.getCode() == 61) {
					String clientMac = String.format("%s %s %s %s %s %s", data[i], data[i + 1], data[i + 2],
							data[i + 3], data[i + 4], data[i + 5]);
					option.addField(new Field(Dhcp.CLIENT_MAC_ADDRESS, clientMac, clientMac.replace(' ', ':')));
					i += 4;
					String clientIp = String.format("%s %s %s %s", data[i], data[i + 1], data[i + 2], data[i + 3]);
					option.addField(new Field(Dhcp.CLIENT_IP_ADDRESS, clientIp,
							NetworkanalyzerTools.decodeAddressIp(clientIp)));
					options.addField(option);

					continue;
				}

				if (dOption.getDecodetype().equals(DhcpOption.IP)) {
					Fields valuesOption;
					valuesOption = new Fields("IP ADDRESSES");
					for (int j = 0; j < l; j += 4) {
						valuesOption = new Fields(Ip.IPS_ADRESSES.getName());
						String ips = String.format("%s %s %s %s", data[j + i], data[j + 1 + i], data[j + 2 + i],
								data[j + 3 + i]);
						valuesOption.addField(
								new Field(new Entry(name, 32), ips, NetworkanalyzerTools.decodeAddressIp(ips)));
						i += 4;
					}

					option.addField(valuesOption);
					options.addField(option);
					continue;
				}

				if (dOption.getDecodetype().equals(DhcpOption.ASCII)) {
					StringBuilder sb = new StringBuilder();

					for (int j = 0; j < l; j++) {
						sb.append(data[i + j]);
						i++;
					}
					option.addField(
							new Field(new Entry(name, l), sb.toString(), NetworkanalyzerTools.toAscii(sb.toString())));
					options.addField(option);
					continue;
				}

				if (dOption.getDecodetype().equals(DhcpOption.HEXA)) {
					StringBuilder sb = new StringBuilder();

					for (int j = 0; j < l; j++) {
						sb.append(data[i + j]);
						i++;
					}
					Entry e = DhcpOption.getEntryTypeDhcp(Integer.parseInt(sb.toString(), 16));
					option.addField(new Field(e == null ? new Entry(name, l) : e, sb.toString(), e.getName()));
					options.addField(option);

					continue;

				}

				if (dOption.getDecodetype().equals(DhcpOption.INT)) {
					StringBuilder sb = new StringBuilder();

					for (int j = 0; j < l; j++) {
						sb.append(data[i + j]);
						i++;
					}
					option.addField(
							new Field(new Entry(name, l), sb.toString(), Integer.parseInt(sb.toString(), 16) + ""));
					options.addField(option);
					continue;
				}
				if (dOption.getDecodetype().equals(DhcpOption.BYTE)) {
					int j;
					for (j = 0; j < l; j++) {
						option.addField(
								new Field(new Entry(name, 8), data[i + j], Integer.parseInt(data[i + j], 16) + ""));
					}
					i += j;

					options.addField(option);
					continue;

				}
				if (dOption.getDecodetype().equals(DhcpOption.TIME)) {
					StringBuilder sb = new StringBuilder();

					for (int j = 0; j < l; j++) {
						sb.append(data[i + j]);
						i++;
					}
					int sec = Integer.parseInt(sb.toString(), 16);
					int min = sec / 60;
					sec %= 60;
					int heure = min / 60;
					min %= 60;

					option.addField(
							new Field(new Entry(name, l), sb.toString(), heure + " h " + min + " m " + sec + " s"));
					options.addField(option);
					continue;

				}

			}

		}

		return options;

	}

}
