package fr.networkanalyzer.model.options;

import fr.networkanalyzer.model.fields.Entry;

public enum DhcpOption {

	PAD(0, "Pad", DhcpOptionTypes.EMPTY_OPTION), SUBNET_MASK(1, "Subnet Mask", DhcpOptionTypes.IP_OPTION),
	ROUTER(3, "Router", DhcpOptionTypes.IP_OPTION), DOMAIN_SERVER(6, "Domain Server", DhcpOptionTypes.IP_OPTION),
	HOSTNAME(12, "Hostname", DhcpOptionTypes.ASCII_OPTION),
	BROADCAST_ADDRESS(28, "Broadcast Address", DhcpOptionTypes.IP_OPTION),
	VENDOR_SPECIFIC(43, "Vendor Specific", DhcpOptionTypes.HEXA_OPTION),
	ADDRESS_REQUEST(50, "Address Request", DhcpOptionTypes.IP_OPTION),
	ADDRESS_TIME(51, "Address Time", DhcpOptionTypes.TIME_OPTION),
	DHCP_MSG_TYPE(53, "DHCP Msg Type", DhcpOptionTypes.HEXA_OPTION),
	DHCP_SERVER_ID(54, "DHCP Server Id", DhcpOptionTypes.IP_OPTION),
	PARAMETER_LIST(55, "Parameter List", DhcpOptionTypes.LISTE_OPTION),
	DHCP_MAX_MSG_SIZE(57, "DHCP Max Msg Size", DhcpOptionTypes.INT_OPTION),
	RENEWAL_TIME(58, "Renewal Time", DhcpOptionTypes.TIME_OPTION),
	REBINDING_TIME(59, "Rebinding Time", DhcpOptionTypes.TIME_OPTION),
	CLASS_ID(60, "Class Id", DhcpOptionTypes.ASCII_OPTION), CLIENT_ID(61, "Client Id", DhcpOptionTypes.UKNOWN_OPTION),
	END(255, "End", DhcpOptionTypes.EMPTY_OPTION), UNKNOW(-1, "Unknow Option", DhcpOptionTypes.UKNOWN_OPTION);

	private int code;
	private String name;
	private DhcpOptionTypes type;

	private DhcpOption(int code, String name, DhcpOptionTypes type) {
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
		return TypeDhcp.getEntryByCode(number);
	}

	public int getCode() {
		return code;
	}

	public String getName() {
		return name;
	}

	public DhcpOptionTypes getType() {
		return type;
	}

}