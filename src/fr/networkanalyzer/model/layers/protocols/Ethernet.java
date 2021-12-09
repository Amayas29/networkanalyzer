package fr.networkanalyzer.model.layers.protocols;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerDataLink;
import fr.networkanalyzer.model.layers.ILayerNetwork;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public class Ethernet extends AbstractLayer implements ILayerDataLink {

	public static final String ARP = "08 06";
	public static final String IPV4 = "08 00";
	public static final String IPV6 = "86 DD";

	public static final Entry<String, Integer> DEST_ADDRESS = new Entry<>("Destination Address", 48);
	public static final Entry<String, Integer> SRC_ADDRESS = new Entry<>("Source Address", 48);
	public static final Entry<String, Integer> TYPE = new Entry<>("Type", 16);
	public static final Entry<String, Integer> DATA = new Entry<String, Integer>("UNKNOW Data", 0);

	private ILayerNetwork included;

	@Override
	public Integer getTotalLength() {
		if(getIncluded()!= null)
			return 14 + included.getTotalLength();
		return 14 + getField(DATA.getKey()).getLength()/8;
	}

	@Override
	public void accept(ILayerVisitor visitor) throws NetworkAnalyzerException {
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
		fs.add(getField(DEST_ADDRESS.getKey()));
		fs.add(getField(SRC_ADDRESS.getKey()));
		fs.add(getField(TYPE.getKey()));
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
		return "ETHERNET";
	}

	@Override
	public String toString() {
		if (included != null)
			return super.toString().concat(included.toString());
		return super.toString();
	}
	
	
}