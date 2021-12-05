package fr.networkanalyzer.model.layers.protocols;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerNetwork;
import fr.networkanalyzer.model.layers.ILayerTransport;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public class Ip extends AbstractLayer implements ILayerNetwork {

	public static final int ICMP = 1;
	public static final int UDP = 17;
	public static final int TCP = 6;

	public static final Entry VERSION = new Entry("Version", 4);
	public static final Entry IHL = new Entry("IHL", 4);
	public static final Entry TOS = new Entry("TOS", 8);
	public static final Entry TOTAL_LENGTH = new Entry("Total Length", 16);
	public static final Entry IDENTIFICATION = new Entry("Identification", 16);
	public static final Entry R = new Entry("R", 1);
	public static final Entry DF = new Entry("DF", 1);
	public static final Entry MF = new Entry("MF", 1);
	public static final Entry FRAGMENT_OFFSET = new Entry("Fragment Offset", 13);
	public static final Entry TTL = new Entry("TTL", 8);
	public static final Entry PROTOCOL = new Entry("Protocol", 8);
	public static final Entry HEADER_CHECKSUM = new Entry("Header Checksum", 16);
	public static final Entry SRC_ADDRESS = new Entry("Source Address", 32);
	public static final Entry DEST_ADDRESS = new Entry("Destination Address", 32);
	public static final Entry FRAGMENTS = new Entry("Fragments", 16);
	public static final Entry OPTIONS = new Entry("Options", Integer.MAX_VALUE);
	public static final Entry IPS_ADRESSES = new Entry("Ips adresses option", Integer.MAX_VALUE);
	private ILayerTransport included;

	@Override
	public Integer getTotalLength() {
		return Integer.parseInt(getField(TOTAL_LENGTH.getName()).getValueDecoded());
	}

	@Override
	public void accept(ILayerVisitor visitor) throws NetworkAnalyzerException {
		visitor.visit(this);
	}

	@Override
	public ILayerTransport getIncluded() {
		return included;
	}

	@Override
	public void setIncluded(ILayerTransport layer) {
		this.included = layer;
	}

	@Override
	public List<IField> getFields() {
		List<IField> fs = new ArrayList<>();

		fs.add(getField(VERSION.getName()));
		fs.add(getField(IHL.getName()));
		fs.add(getField(TOS.getName()));
		fs.add(getField(TOTAL_LENGTH.getName()));
		fs.add(getField(IDENTIFICATION.getName()));
		fs.add(getField(FRAGMENTS.getName()));
		fs.add(getField(TTL.getName()));
		fs.add(getField(PROTOCOL.getName()));
		fs.add(getField(HEADER_CHECKSUM.getName()));
		fs.add(getField(SRC_ADDRESS.getName()));
		fs.add(getField(DEST_ADDRESS.getName()));
		IField options = getField(OPTIONS.getName());

		if (options != null)
			fs.add(options);

		return fs;
	}

	@Override
	public String getEncapsulatedProtocol() {
		return included.getEncapsulatedProtocol();
	}

	@Override
	public String getName() {
		return "IP";
	}

	@Override
	public String toString() {
		return super.toString().concat(included.toString());
	}

}