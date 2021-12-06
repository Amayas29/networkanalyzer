package fr.networkanalyzer.model.tools;

import fr.networkanalyzer.model.fields.Entry;

public enum DhcpOption {

	PAD(0, "Pad", "", false), SUBNET_MASK(1, "Subnet Mask", "ip", true), ROUTER(3, "Router", "ip", true),
	DOMAIN_SERVER(6, "Domain Server", "ip", true), HOSTNAME(12, "Hostname", "ascii", true),
	BROADCAST_ADDRESS(28, "Broadcast Address", "ip", true), VENDOR_SPECIFIC(43, "Vendor Specific", "hexa", true),
	ADDRESS_REQUEST(50, "Address Request", "ip", true), ADDRESS_TIME(51, "Address Time", "time", true),
	DHCP_MSG_TYPE(53, "DHCP Msg Type", "hexa", true), DHCP_SERVER_ID(54, "DHCP Server Id", "ip", true),
	PARAMETER_LIST(55, "Parameter List", "bytes", true), DHCP_MAX_MSG_SIZE(57, "DHCP Max Msg Size", "int", true),
	RENEWAL_TIME(58, "Renewal Time", "time", true), REBINDING_TIME(59, "Rebinding Time", "time", true),
	CLASS_ID(60, "Class Id", "ascii", true), CLIENT_ID(61, "Client Id", "", true), END(255, "End", "", false),
	UNKNOW(-1, "Unknow", "UNKNOW", true);

	public static final String IP = "ip";
	public static final String ASCII = "ascii";
	public static final String HEXA = "hexa";
	public static final String TIME = "time";
	public static final String INT = "int";
	public static final String BYTE = "bytes";

	public static final Entry REQUEST = new Entry("Request", 3);

	public static final Entry ACK = new Entry("ACK", 5);

	public static final Entry DISCOVER = new Entry("Discover", 1);

	public static final Entry OFFER = new Entry("Offer", 2);
	private int code;
	private String name;
	private boolean length;
	private String decode;

	private DhcpOption(int code, String name, String decode, boolean length) {
		this.code = code;
		this.name = name;
		this.decode = decode;
		this.length = length;
	}

	public static DhcpOption getOptionByCode(String code) {
		int codeDecoded = Integer.parseInt(code, 16);

		DhcpOption[] options = values();

		for (int j = 0; j < options.length; j++)
			if (codeDecoded == options[j].code)
				return options[j];

		return DhcpOption.UNKNOW;
	}

	public static Entry getEntryTypeDhcp(int number) {
		return TypeDhcp.getEntryByCode(number);
	}

	public int getCode() {
		return code;
	}

	public String getName() {
		return name;
	}

	public boolean hasLength() {
		return length;
	}

	public String getDecodetype() {
		return decode;
	}

}