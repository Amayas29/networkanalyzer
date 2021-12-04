package fr.networkanalyzer.model.layers.protocols;

import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerTransport;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public class Icmp extends AbstractLayer implements ILayerTransport {

	public static final Entry TYPE = new Entry("Type",8);
	public static final Entry Code = new Entry("Code",8);
	public static final Entry CHECKSUM = new Entry("Checksum",16);
	public static final Entry IDENTIFIER = new Entry("Identifier",16);
	public static final Entry SEQUENCE_NUMBER = new Entry("Sequence number",8);
	@Override
	public void accept(ILayerVisitor visitor) throws NetworkAnalyzerException {
		visitor.visit(this);
	}

	@Override
	public List<IField> getFields() {
		return null;
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
		// TODO Auto-generated method stub
		return super.toString();
	}

}