package fr.networkanalyzer.model.options;

import fr.networkanalyzer.model.decoder.DhcpDecoder;
import fr.networkanalyzer.model.fields.Entry;

public enum DhcpOption {

	PAD(0, "Pad", DhcpOptionType.EMPTY_OPTION), SUBNET_MASK(1, "Subnet Mask", DhcpOptionType.IP_OPTION),
	ROUTER(3, "Router", DhcpOptionType.IP_OPTION), DOMAIN_SERVER(6, "Domain Server", DhcpOptionType.IP_OPTION),
	HOSTNAME(12, "Hostname", DhcpOptionType.ASCII_OPTION),
	BROADCAST_ADDRESS(28, "Broadcast Address", DhcpOptionType.IP_OPTION),
	VENDOR_SPECIFIC(43, "Vendor Specific", DhcpOptionType.HEXA_OPTION),
	ADDRESS_REQUEST(50, "Address Request", DhcpOptionType.IP_OPTION),
	ADDRESS_TIME(51, "Address Time", DhcpOptionType.TIME_OPTION),
	DHCP_MSG_TYPE(53, "DHCP Msg Type", DhcpOptionType.HEXA_OPTION),
	DHCP_SERVER_ID(54, "DHCP Server Id", DhcpOptionType.IP_OPTION),
	PARAMETER_LIST(55, "Parameter List", DhcpOptionType.LISTE_OPTION),
	DHCP_MAX_MSG_SIZE(57, "DHCP Max Msg Size", DhcpOptionType.INT_OPTION),
	RENEWAL_TIME(58, "Renewal Time", DhcpOptionType.TIME_OPTION),
	REBINDING_TIME(59, "Rebinding Time", DhcpOptionType.TIME_OPTION),
	CLASS_ID(60, "Class Id", DhcpOptionType.ASCII_OPTION), CLIENT_ID(61, "Client Id", DhcpOptionType.UKNOWN_OPTION),
	END(255, "End", DhcpOptionType.EMPTY_OPTION), UNKNOW(-1, "Unknow Option", DhcpOptionType.UKNOWN_OPTION);

	private int code;
	private String name;
	private DhcpOptionType type;

	private DhcpOption(int code, String name, DhcpOptionType type) {
		this.code = code;
		this.name = name;
		this.type = type;
	}

	public static DhcpOption getOptionByCode(String code) {
		int codeDecoded = Integer.parseInt(code, 16);

		DhcpOption[] options = values();

		for (int j = 0; j < options.length; j++)
			if (codeDecoded == options[j].code)
				return options[j];

		return UNKNOW;
	}

	public static Entry<String, Integer> getEntryTypeDhcp(int number) {
		return DhcpDecoder.getType(number);
	}

	public int getCode() {
		return code;
	}

	public String getName() {
		return name;
	}

	public DhcpOptionType getType() {
		return type;
	}

}