package fr.networkanalyzer.model.layers.protocols;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.Fields;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerApplication;
import fr.networkanalyzer.model.options.DhcpOption;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public class Dhcp extends AbstractLayer implements ILayerApplication {

	public static final Entry<String, Integer> BOOT_REQUEST = new Entry<>("Boot Request", 1);
	public static final Entry<String, Integer> BOOT_REPLY = new Entry<>("Boot Reply", 2);

	public static final Entry<String, Integer> MESSAGE_TYPE = new Entry<>("Message Type", 8);
	public static final Entry<String, Integer> HARDWARE_TYPE = new Entry<>("Hardware Type", 8);
	public static final Entry<String, Integer> HARDWARE_ADDRESS_LENGTH = new Entry<>("Hardware Address Length", 8);
	public static final Entry<String, Integer> HOPS = new Entry<>("Hops", 8);
	public static final Entry<String, Integer> TRANSACTION_ID = new Entry<>("Transaction Id", 32);
	public static final Entry<String, Integer> SECONDS_ELAPSED = new Entry<>("Seconds Elapsed", 16);
	public static final Entry<String, Integer> BROADCAST = new Entry<>("Broadcast Flag", 1);
	public static final Entry<String, Integer> RESERVED = new Entry<>("Reserved Flag", 15);
	public static final Entry<String, Integer> CLIENT_IP_ADDRESS = new Entry<>("Client Ip Address", 32);
	public static final Entry<String, Integer> YOUR_IP_ADDRESS = new Entry<>("Your Ip Address", 32);
	public static final Entry<String, Integer> NEXT_SERVER_IP_ADDRESS = new Entry<>("Next Server Ip Address", 32);
	public static final Entry<String, Integer> RELAY_AGENT_IP_ADDRESS = new Entry<>("Gateway Ip Address", 32);
	public static final Entry<String, Integer> CLIENT_MAC_ADDRESS = new Entry<>("Client Mac Address", 0);
	public static final Entry<String, Integer> CLIENT_HARDWARE_ADDRESS_PADDING = new Entry<>(
			"Client Hardware Address Padding", 128);
	public static final Entry<String, Integer> SERVER_HOST_NAME = new Entry<>("Server Host Name", 512);
	public static final Entry<String, Integer> BOOT_FILE = new Entry<>("Boot File", 1024);
	public static final Entry<String, Integer> MAGIC_COOKIE = new Entry<>("Magic Cookie", 32);

	public static final Entry<String, Integer> FLAGS = new Entry<>("Flags", 16);
	public static final Entry<String, Integer> OPTIONS = new Entry<>("Options", Integer.MAX_VALUE);

	public static Entry<String, Integer> getMessageType(int type) {
		if (type == 1)
			return BOOT_REQUEST;
		if (type == 2)
			return BOOT_REPLY;
		return null;
	}

	@Override
	public void accept(ILayerVisitor visitor) throws NetworkAnalyzerException {
		visitor.visit(this);
	}

	@Override
	public List<IField> getFields() {
		List<IField> fs = new ArrayList<>();
		fs.add(getField(MESSAGE_TYPE.getKey()));
		fs.add(getField(HARDWARE_TYPE.getKey()));
		fs.add(getField(HARDWARE_ADDRESS_LENGTH.getKey()));
		fs.add(getField(HOPS.getKey()));
		fs.add(getField(TRANSACTION_ID.getKey()));
		fs.add(getField(SECONDS_ELAPSED.getKey()));
		fs.add(getField(FLAGS.getKey()));
		fs.add(getField(CLIENT_IP_ADDRESS.getKey()));
		fs.add(getField(YOUR_IP_ADDRESS.getKey()));
		fs.add(getField(NEXT_SERVER_IP_ADDRESS.getKey()));
		fs.add(getField(RELAY_AGENT_IP_ADDRESS.getKey()));
		fs.add(getField(CLIENT_MAC_ADDRESS.getKey()));
		fs.add(getField(CLIENT_HARDWARE_ADDRESS_PADDING.getKey()));
		fs.add(getField(SERVER_HOST_NAME.getKey()));
		fs.add(getField(BOOT_FILE.getKey()));
		fs.add(getField(MAGIC_COOKIE.getKey()));

		IField opts = getField(OPTIONS.getKey());

		if (opts != null)
			for (IField f : opts.getChildrens())
				fs.add(f);

		return fs;
	}

	@Override
	public String getEncapsulatedProtocol() {
		DhcpOption o53 = DhcpOption.DHCP_MSG_TYPE;

		IField value = null;
		try {
			Fields options = (Fields) getField(OPTIONS.getKey());
			Fields opt = (Fields) options.getField(o53.getName());

			for (IField f : opt.getChildrens())
				if (!f.getName().equals("Type") && !f.getName().equals("Length")) {
					value = f;
					break;
				}

		} catch (Exception e) {
			return "DHCP";
		}

		return "DHCP (".concat(value.getValueDecoded()).concat(")");
	}

	@Override
	public String getName() {
		return "DHCP";
	}

	@Override
	public String toString() {
		return super.toString();
	}

}