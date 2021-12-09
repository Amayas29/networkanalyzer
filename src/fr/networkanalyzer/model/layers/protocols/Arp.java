package fr.networkanalyzer.model.layers.protocols;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerNetwork;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public class Arp extends AbstractLayer implements ILayerNetwork {

	private static final int LENGTH = 28;

	public static final Entry<String, Integer> HARDWARE_TYPE = new Entry<>("Hardware type", 16);
	public static final Entry<String, Integer> PROTOCOL_TYPE = new Entry<>("Protocol type", 16);
	public static final Entry<String, Integer> HARDWARE_SIZE = new Entry<>("Hardware size", 8);
	public static final Entry<String, Integer> PROTOCOL_SIZE = new Entry<>("Protocol size", 8);
	public static final Entry<String, Integer> OPCODE = new Entry<>("Opcode", 16);
	public static final Entry<String, Integer> SOURCE_HARDWARE_ADDRESS = new Entry<>("Source Hardware Address", 0);
	public static final Entry<String, Integer> SOURCE_PROTOCOL_ADDRESS = new Entry<>("Source Protocol Address", 0);
	public static final Entry<String, Integer> DESTINATION_HARDWARE_ADDRESS = new Entry<>(
			"Destination Hardware Address", 0);
	public static final Entry<String, Integer> DESTINATION_PROTOCOL_ADDRESS = new Entry<>(
			"Destination Protocol Address", 0);

	@Override
	public void accept(ILayerVisitor visitor) throws NetworkAnalyzerException {
		visitor.visit(this);
	}

	@Override
	public Integer getTotalLength() {
		return LENGTH;
	}

	@Override
	public IField getField(String field) {
		if (field.equals(Ip.SRC_ADDRESS.getKey()))
			return super.getField(SOURCE_PROTOCOL_ADDRESS.getKey());

		if (field.equals(Ip.DEST_ADDRESS.getKey()))
			return super.getField(DESTINATION_PROTOCOL_ADDRESS.getKey());

		return super.getField(field);
	}

	@Override
	public List<IField> getFields() {
		List<IField> fs = new ArrayList<>();
		fs.add(getField(HARDWARE_TYPE.getKey()));
		fs.add(getField(PROTOCOL_TYPE.getKey()));
		fs.add(getField(HARDWARE_SIZE.getKey()));
		fs.add(getField(PROTOCOL_SIZE.getKey()));
		fs.add(getField(OPCODE.getKey()));
		fs.add(getField(SOURCE_HARDWARE_ADDRESS.getKey()));
		fs.add(getField(SOURCE_PROTOCOL_ADDRESS.getKey()));
		fs.add(getField(DESTINATION_HARDWARE_ADDRESS.getKey()));
		fs.add(getField(DESTINATION_PROTOCOL_ADDRESS.getKey()));
		return fs;
	}

	@Override
	public String getEncapsulatedProtocol() {
		return "ARP";
	}

	@Override
	public String getName() {
		return "ARP";
	}

}