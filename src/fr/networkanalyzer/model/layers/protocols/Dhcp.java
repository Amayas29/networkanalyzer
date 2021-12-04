package fr.networkanalyzer.model.layers.protocols;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerApplication;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public class Dhcp extends AbstractLayer implements ILayerApplication {

	public static final Entry MESSAGE_TYPE = new Entry("Message Type", 8);
	public static final Entry HARDWARE_TYPE = new Entry("Hardware Type", 8);
	public static final Entry HARDWARE_ADDRESS_LENGTH = new Entry("Hardware Address Length", 8);
	public static final Entry HOPS = new Entry("Hops", 8);
	public static final Entry TRANSACTION_ID = new Entry("Transaction Id", 32);
	public static final Entry SECONDS_ELAPSED = new Entry("Seconds Elapsed", 16);
	public static final Entry BROADCAST = new Entry("Broadcast Flag", 1);
	public static final Entry RESERVED = new Entry("Reserved Flag", 15);
	public static final Entry CLIENT_IP_ADDRESS = new Entry("Client Ip Address", 32);
	public static final Entry YOUR_IP_ADDRESS = new Entry("Your Ip Address", 32);
	public static final Entry NEXT_SERVER_IP_ADDRESS = new Entry("Next Server Ip Address", 32);
	public static final Entry RELAY_AGENT_IP_ADDRESS = new Entry("Relay Agent Ip Address", 32);
	public static final Entry CLIENT_MAC_ADDRESS = new Entry("Client Mac Address", 128);
//	TODO
//	public static final Entry CLIENT_HARDWARE_ADDRESS_PADDING = new Entry("Client Hardware Address Padding", 80);
	public static final Entry SERVER_HOST_NAME = new Entry("Server Host Name", 512);
	public static final Entry BOOT_FILE = new Entry("Boot File", 1024);
	public static final Entry MAGIC_COOKIE = new Entry("Magic Cookie", 32);
	public static final Entry FLAGS = new Entry("Flags", 16);

	@Override
	public void accept(ILayerVisitor visitor) throws NetworkAnalyzerException {
		visitor.visit(this);
	}

	@Override
	public List<IField> getFields() {
		List<IField> fs = new ArrayList<>();
		fs.add(getField(MESSAGE_TYPE.NAME));
		fs.add(getField(HARDWARE_TYPE.NAME));
		fs.add(getField(HARDWARE_ADDRESS_LENGTH.NAME));
		fs.add(getField(HOPS.NAME));
		fs.add(getField(TRANSACTION_ID.NAME));
		fs.add(getField(SECONDS_ELAPSED.NAME));
		fs.add(getField(FLAGS.NAME));
		fs.add(getField(CLIENT_IP_ADDRESS.NAME));
		fs.add(getField(YOUR_IP_ADDRESS.NAME));
		fs.add(getField(NEXT_SERVER_IP_ADDRESS.NAME));
		fs.add(getField(RELAY_AGENT_IP_ADDRESS.NAME));
		fs.add(getField(CLIENT_MAC_ADDRESS.NAME));
//		fs.add(getField(CLIENT_HARDWARE_ADDRESS_PADDING.NAME));
		fs.add(getField(SERVER_HOST_NAME.NAME));
		fs.add(getField(BOOT_FILE.NAME));
//		fs.add(getField(MAGIC_COOKIE.NAME));

		return fs;
	}

	@Override
	public String getEncapsulatedProtocol() {
		return "DHCP";
	}

	@Override
	public String getName() {
		return "DHCP";
	}

}