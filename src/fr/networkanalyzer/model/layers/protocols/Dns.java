package fr.networkanalyzer.model.layers.protocols;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.Entry;
import fr.networkanalyzer.model.fields.Fields;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerApplication;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public class Dns extends AbstractLayer implements ILayerApplication {

	public static final Entry IDENTIFIER = new Entry("Identification", 16);

	public static final Entry RESPONSE = new Entry("Response", 1);
	public static final Entry OPCODE = new Entry("Opcode", 4);
	public static final Entry AUTHORITATIVE = new Entry("Authoritative", 1);
	public static final Entry TRUNCATED = new Entry("Truncated", 1);
	public static final Entry RECURSION_DESIRED = new Entry("Recursion Desired", 1);
	public static final Entry RECURSION_AVAILABLE = new Entry("Recursion available", 1);
	public static final Entry Z = new Entry("Z", 1);
	public static final Entry ANSWER_AUTHENTICATED = new Entry("Answer authenticated", 1);
	public static final Entry NON_AUTHENTICATED_DATA = new Entry("Non authenticated data", 1);
	public static final Entry REPLY_CODE = new Entry("Reply code", 4);

	public static final Entry FLAGS = new Entry("Flags", 16);
	public static final Entry QUESTIONS_NUMBER = new Entry("Questions number", 16);
	public static final Entry ANSWER_RRS_NUMBER = new Entry("# Answer RRS", 16);
	public static final Entry AUTHORITY_RRS_NUMBER = new Entry("# Authority RRs", 16);
	public static final Entry ADDITIONAL_RRS_NUMBER = new Entry("# Additional RRs", 16);
	public static final Entry QUESTIONS = new Entry("Questions", 0);
	public static final Entry ANSWER = new Entry("Answer", 0);
	public static final Entry AUTHORITY = new Entry("Authority", 0);
	public static final Entry ADDITIONAL_INFO = new Entry("Additional info", 0);

	@Override
	public void accept(ILayerVisitor visitor) throws NetworkAnalyzerException {
		visitor.visit(this);
	}

	@Override
	public List<IField> getFields() {
		List<IField> fs = new ArrayList<>();

		fs.add(getField(IDENTIFIER.getName()));

		Fields flags = (Fields) getField(FLAGS.getName());

//		IField response = flags.getField(RESPONSE.getName());
//		if (response.getValueDecoded().equals("0")) {
//			flags.removeField(AUTHORITATIVE.getName());
//			flags.removeField(RECURSION_AVAILABLE.getName());
//			flags.removeField(ANSWER_AUTHENTICATED.getName());
//			flags.removeField(REPLY_CODE.getName());
//		}

		fs.add(flags);
		fs.add(getField(QUESTIONS_NUMBER.getName()));
		fs.add(getField(ANSWER_RRS_NUMBER.getName()));
		fs.add(getField(AUTHORITY_RRS_NUMBER.getName()));
		fs.add(getField(ADDITIONAL_RRS_NUMBER.getName()));

		IField field = getField(QUESTIONS.getName());
		if (field != null)
			fs.add(field);

		field = getField(ANSWER.getName());
		if (field != null)
			fs.add(field);

		field = getField(AUTHORITY.getName());
		if (field != null)
			fs.add(field);

		field = getField(ADDITIONAL_INFO.getName());
		if (field != null)
			fs.add(field);

		return fs;
	}

	@Override
	public String getEncapsulatedProtocol() {
		return "DNS";
	}

	@Override
	public String getName() {
		return "DNS";
	}

}