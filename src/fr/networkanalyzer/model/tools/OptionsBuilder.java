package fr.networkanalyzer.model.tools;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.Field;
import fr.networkanalyzer.model.fields.Fields;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.protocols.Ip;

public class OptionsBuilder {

	public static IField buildIpOptions(String header) throws NetworkAnalyzerException {

		Fields options = new Fields(Ip.OPTIONS.NAME);

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
				fieldsAdresses = new Fields(Ip.IPS_ADRESSES.NAME);
				String ips = String.format("%s %s %s %s", data[j], data[j + 1], data[j + 2], data[j + 3]);
				fieldsAdresses
						.addField(new Field(new Entry("adresse", 32), ips, NetworkanalyzerTools.decodeAddressIp(ips)));
				i += 4;
			}
			option.addField(fieldsAdresses);
			options.addField(option);

		}

		return options;
	}

}
