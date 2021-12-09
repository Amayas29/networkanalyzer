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
	public static final int DHCP_1 = 67;
	public static final int DHCP_2 = 68;

	public static final Entry<String, Integer> SRC_PORT = new Entry<>("Source Port", 16);
	public static final Entry<String, Integer> DEST_PORT = new Entry<>("Destination Port", 16);
	public static final Entry<String, Integer> LENGTH = new Entry<>("Length", 16);
	public static final Entry<String, Integer> CHECKSUM = new Entry<>("Checksum", 16);
	public static final Entry<String, Integer> DATA = new Entry<>("Data", 0);

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
		fs.add(getField(SRC_PORT.getKey()));
		fs.add(getField(DEST_PORT.getKey()));
		fs.add(getField(LENGTH.getKey()));
		fs.add(getField(CHECKSUM.getKey()));

		IField data = getField(DATA.getKey());
		if (data != null)
			fs.add(data);

		return fs;
	}

	@Override
	public String getEncapsulatedProtocol() {
		if (included != null)
			return included.getEncapsulatedProtocol();
		return "UDP";
	}

	@Override
	public String getName() {
		return "UDP";
	}

	@Override
	public String toString() {
		if (included != null)
			return super.toString().concat(included.toString());

		return super.toString();
	}
}