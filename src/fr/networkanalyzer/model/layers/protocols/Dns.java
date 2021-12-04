package fr.networkanalyzer.model.layers.protocols;

import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerApplication;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public class Dns extends AbstractLayer implements ILayerApplication {

	
	public static final Entry IDENTIFIER = new Entry("Identification",16);
	public static final Entry FLAGS = new Entry("Flags",16);
	public static final Entry QUESTIONS_NUMBER = new Entry("Questions number",16);
	public static final Entry ANSWER_RRS_NUMBER = new Entry("# Answer RRS",16);
	public static final Entry AUTHORITY_RRS_NUMBER = new Entry("# Authority RRs",16);
	public static final Entry ADDITIONAL_RRS_NUMBER = new Entry("# Additional RRs",16);
	public static final Entry QUESTIONS = new Entry("Questions",32);
	public static final Entry ANSWER = new Entry("Answer",32);
	public static final Entry AUTHORITY = new Entry("Authority",32);
	public static final Entry ADDITIONAL_INFO = new Entry("Additional info",32);


	
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
		return "DNS";
	}
	
	@Override
	public String getName() {
		return "DNS";
	}

	@Override
	public String toString() {
		return super.toString();
	}

}