package fr.networkanalyzer.model.layers.protocols;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerApplication;
import fr.networkanalyzer.model.layers.ILayerTransport;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public class Udp extends AbstractLayer implements ILayerTransport {

	public static final int DNS = 53;
	public static final int DHCP = 67;

	public static final Entry SRC_PORT = new Entry("Source Port", 16);
	public static final Entry DEST_PORT = new Entry("Destination Port", 16);
	public static final Entry LENGTH = new Entry("Length", 16);
	public static final Entry CHECKSUM = new Entry("Checksum", 16);

	private ILayerApplication included;

	@Override
	public void accept(ILayerVisitor visitor) throws NetworkAnalyzerException {
		visitor.visit(this);
	}

	@Override
	public ILayerApplication getIncluded() {
		return included;
	}

	@Override
	public void setIncluded(ILayerApplication layer) {
		this.included = layer;
	}

	@Override
	public List<IField> getFields() {
		List<IField> fs = new ArrayList<>();
		fs.add(getField(SRC_PORT.NAME));
		fs.add(getField(DEST_PORT.NAME));
		fs.add(getField(LENGTH.NAME));
		fs.add(getField(CHECKSUM.NAME));
		return fs;
	}

	@Override
	public String getEncapsulatedProtocol() {
		return included.getEncapsulatedProtocol();
	}
	@Override
	public String getName() {
		return "UDP";
	}
}