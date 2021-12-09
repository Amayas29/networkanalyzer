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

	public static final Entry<String, Integer> VERSION = new Entry<>("Version", 4);
	public static final Entry<String, Integer> IHL = new Entry<>("IHL", 4);
	public static final Entry<String, Integer> TOS = new Entry<>("TOS", 8);
	public static final Entry<String, Integer> TOTAL_LENGTH = new Entry<>("Total Length", 16);
	public static final Entry<String, Integer> IDENTIFICATION = new Entry<>("Identification", 16);
	public static final Entry<String, Integer> R = new Entry<>("R", 1);
	public static final Entry<String, Integer> DF = new Entry<>("DF", 1);
	public static final Entry<String, Integer> MF = new Entry<>("MF", 1);
	public static final Entry<String, Integer> FRAGMENT_OFFSET = new Entry<>("Fragment Offset", 13);
	public static final Entry<String, Integer> TTL = new Entry<>("TTL", 8);
	public static final Entry<String, Integer> PROTOCOL = new Entry<>("Protocol", 8);
	public static final Entry<String, Integer> HEADER_CHECKSUM = new Entry<>("Header Checksum", 16);
	public static final Entry<String, Integer> SRC_ADDRESS = new Entry<>("Source Address", 32);
	public static final Entry<String, Integer> DEST_ADDRESS = new Entry<>("Destination Address", 32);
	public static final Entry<String, Integer> FRAGMENTS = new Entry<>("Fragments", 16);
	public static final Entry<String, Integer> OPTIONS = new Entry<>("Options", Integer.MAX_VALUE);
	public static final Entry<String,Integer> DATA = new Entry<String, Integer>("DATA", 0);

	private ILayerTransport included;

	@Override
	public Integer getTotalLength() {
		return Integer.parseInt(getField(TOTAL_LENGTH.getKey()).getValueDecoded());
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

		fs.add(getField(VERSION.getKey()));
		fs.add(getField(IHL.getKey()));
		fs.add(getField(TOS.getKey()));
		fs.add(getField(TOTAL_LENGTH.getKey()));
		fs.add(getField(IDENTIFICATION.getKey()));
		fs.add(getField(FRAGMENTS.getKey()));
		fs.add(getField(TTL.getKey()));
		fs.add(getField(PROTOCOL.getKey()));
		fs.add(getField(HEADER_CHECKSUM.getKey()));
		fs.add(getField(SRC_ADDRESS.getKey()));
		fs.add(getField(DEST_ADDRESS.getKey()));
		IField options = getField(OPTIONS.getKey());
		
		if (options != null)
			fs.add(options);

		IField data = getField(DATA.getKey());
		if (data != null)
			fs.add(data);
		return fs;
	}

	@Override
	public String getEncapsulatedProtocol() {
		if (included != null)
			return included.getEncapsulatedProtocol();
		return getName();
	}
	@Override
	public String getName() {
		return "IP";
	}

	@Override
	public String toString() {
		if (included != null)
			return super.toString().concat(included.toString());
		return super.toString();
	}

}