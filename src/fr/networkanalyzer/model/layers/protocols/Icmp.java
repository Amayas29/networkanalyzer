package fr.networkanalyzer.model.layers.protocols;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerTransport;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public class Icmp extends AbstractLayer implements ILayerTransport {

	public static final Entry<String,Integer> TYPE = new Entry<>("Type", 8);
	public static final Entry<String,Integer> CODE = new Entry<>("Code", 8);
	public static final Entry<String,Integer> CHECKSUM = new Entry<>("Checksum", 16);
	public static final Entry<String,Integer> IDENTIFIER = new Entry<>("Identifier", 16);
	public static final Entry<String,Integer> SEQUENCE_NUMBER = new Entry<>("Sequence number", 16);
	public static final Entry<String,Integer> DATA = new Entry<>("Data",0);
	@Override
	public void accept(ILayerVisitor visitor) throws NetworkAnalyzerException {
		visitor.visit(this);
	}

	@Override
	public List<IField> getFields() {
		List<IField> fields = new ArrayList<>();
		fields.add(getField(TYPE.getKey()));
		fields.add(getField(CODE.getKey()));
		fields.add(getField(CHECKSUM.getKey()));
		fields.add(getField(IDENTIFIER.getKey()));
		fields.add(getField(SEQUENCE_NUMBER.getKey()));
		
		return fields;
	}

	@Override
	public String getEncapsulatedProtocol() {
		return "ICMP";
	}

	@Override
	public String getName() {
		return "ICMP";
	}

	@Override
	public String toString() {
		return super.toString();
	}

}