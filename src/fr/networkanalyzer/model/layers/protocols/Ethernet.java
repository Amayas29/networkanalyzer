package fr.networkanalyzer.model.layers.protocols;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.Entry;
import fr.networkanalyzer.model.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerDataLink;
import fr.networkanalyzer.model.layers.ILayerNetwork;
import fr.networkanalyzer.model.layers.ILayerVisitor;

public class Ethernet extends AbstractLayer implements ILayerDataLink {

	public static final String ARP = "08 06";
	public static final String IP = "08 00";

	public static final Entry DEST_ADDRESS = new Entry("Destination Address", 48);
	public static final Entry SRC_ADDRESS = new Entry("Source Address", 48);
	public static final Entry TYPE = new Entry("Type", 16);

	private ILayerNetwork included;

	@Override
	public Integer getTotalLength() {
		return 14 + included.getTotalLength();
	}

	@Override
	public void accept(ILayerVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public ILayerNetwork getIncluded() {
		return included;
	}
	

	@Override
	public void setIncluded(ILayerNetwork layer) {
		this.included = layer;
	}

	@Override
	public List<IField> getFields() {
		List<IField> fs = new ArrayList<>();
		fs.add(getField(SRC_ADDRESS.NAME));
		fs.add(getField(DEST_ADDRESS.NAME));
		fs.add(getField(TYPE.NAME));
		return fs;
	}

	@Override
	public String getEncapsulatedProtocol() {
		return included.getEncapsulatedProtocol();
	}
}