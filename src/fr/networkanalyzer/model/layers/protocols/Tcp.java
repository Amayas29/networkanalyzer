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

public class Tcp extends AbstractLayer implements ILayerTransport {

	public static final int HTTP = 80;
	public static final int IMAP = 143;

	private ILayerApplication included;

	public static final Entry SRC_PORT = new Entry("Source Port", 16);
	public static final Entry DEST_PORT = new Entry("Destination Port", 16);
	public static final Entry SEQUENCE_NUMBER = new Entry("Sequence Number", 32);
	public static final Entry ACKNOWLEDGMENT_NUMBER = new Entry("Acknowledgment Number", 32);
	public static final Entry THL = new Entry("THL", 4);
	public static final Entry RESERVED = new Entry("Reserved", 6);
	public static final Entry URG = new Entry("URG", 1);
	public static final Entry ACK = new Entry("ACK", 1);
	public static final Entry PSH = new Entry("PSH", 1);
	public static final Entry RST = new Entry("RST", 1);
	public static final Entry SYN = new Entry("SYN", 1);
	public static final Entry FIN = new Entry("FIN", 1);
	public static final Entry WINDOW = new Entry("Window", 16);
	public static final Entry CHECKSUM = new Entry("Checksum", 16);
	public static final Entry URGENT_POINTER = new Entry("Urgent Pointer", 16);
	public static final Entry FLAGS = new Entry("Flags", 12);

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
		fs.add(getField(SEQUENCE_NUMBER.NAME));
		fs.add(getField(ACKNOWLEDGMENT_NUMBER.NAME));
		fs.add(getField(THL.NAME));
		fs.add(getField(FLAGS.NAME));
		fs.add(getField(WINDOW.NAME));
		fs.add(getField(CHECKSUM.NAME));
		fs.add(getField(URGENT_POINTER.NAME));

		return fs;
	}

	@Override
	public String getEncapsulatedProtocol() {

		if (included == null)
			return "TCP";

		return included.getEncapsulatedProtocol();
	}
}