package fr.networkanalyzer.model.layers.protocols;

import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerNetwork;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public class Arp extends AbstractLayer implements ILayerNetwork {

	private static final int LENGTH = 28;

	public static final Entry HARDWARE_TYPE = new Entry("Hardware type", 16);
	public static final Entry PROTOCOL = new Entry("Protocol type", 16);
	public static final Entry HLEN = new Entry("HLEN", 4);
	public static final Entry PLEN = new Entry("PLEN", 4);
	public static final Entry OPERATIONS = new Entry("Operations", 8);
	public static final Entry SOURCE_HARDWARE_ADDRESS = new Entry("Source Hardware Address", 32);
	public static final Entry SOURCE_PROTOCOL_ADDRESS = new Entry("Source Protocol Address", 16);
	public static final Entry DESTINATION_HARDWARE_ADDRESS = new Entry("Destination Hardware Address", 8);
	public static final Entry DESTINATION_PROTOCOL_ADDRESS = new Entry("Destination Protocol Address", 16);

	@Override
	public void accept(ILayerVisitor visitor) throws NetworkAnalyzerException {
		visitor.visit(this);
	}

	@Override
	public Integer getTotalLength() {
		return LENGTH;
	}

	@Override
	public List<IField> getFields() {
		return null;
	}

	@Override
	public String getEncapsulatedProtocol() {
		return "ARP";
	}

	@Override
	public String getName() {
		return "ARP";
	}

	@Override
	public String toString() {
		return super.toString();
	}

}