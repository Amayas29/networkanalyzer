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

	public static final Entry<String, Integer> IDENTIFIER = new Entry<>("Identification", 16);

	public static final Entry<String, Integer> RESPONSE = new Entry<>("Response", 1);
	public static final Entry<String, Integer> OPCODE = new Entry<>("Opcode", 4);
	public static final Entry<String, Integer> AUTHORITATIVE = new Entry<>("Authoritative", 1);
	public static final Entry<String, Integer> TRUNCATED = new Entry<>("Truncated", 1);
	public static final Entry<String, Integer> RECURSION_DESIRED = new Entry<>("Recursion Desired", 1);
	public static final Entry<String, Integer> RECURSION_AVAILABLE = new Entry<>("Recursion available", 1);
	public static final Entry<String, Integer> Z = new Entry<>("Z", 1);
	public static final Entry<String, Integer> ANSWER_AUTHENTICATED = new Entry<>("Answer authenticated", 1);
	public static final Entry<String, Integer> NON_AUTHENTICATED_DATA = new Entry<>("Non authenticated data", 1);
	public static final Entry<String, Integer> REPLY_CODE = new Entry<>("Reply code", 4);

	public static final Entry<String, Integer> FLAGS = new Entry<>("Flags", 16);
	public static final Entry<String, Integer> QUESTIONS_NUMBER = new Entry<>("Questions number", 16);
	public static final Entry<String, Integer> ANSWER_RRS_NUMBER = new Entry<>("# Answer RRS", 16);
	public static final Entry<String, Integer> AUTHORITY_RRS_NUMBER = new Entry<>("# Authority RRs", 16);
	public static final Entry<String, Integer> ADDITIONAL_RRS_NUMBER = new Entry<>("# Additional RRs", 16);
	public static final Entry<String, Integer> QUESTIONS = new Entry<>("Questions", 0);
	public static final Entry<String, Integer> ANSWER = new Entry<>("Answer", 0);
	public static final Entry<String, Integer> AUTHORITY = new Entry<>("Authority", 0);
	public static final Entry<String, Integer> ADDITIONAL_INFO = new Entry<>("Additional info", 0);

	@Override
	public void accept(ILayerVisitor visitor) throws NetworkAnalyzerException {
		visitor.visit(this);
	}

	@Override
	public List<IField> getFields() {
		List<IField> fs = new ArrayList<>();

		fs.add(getField(IDENTIFIER.getKey()));

		Fields flags = (Fields) getField(FLAGS.getKey());

		fs.add(flags);
		fs.add(getField(QUESTIONS_NUMBER.getKey()));
		fs.add(getField(ANSWER_RRS_NUMBER.getKey()));
		fs.add(getField(AUTHORITY_RRS_NUMBER.getKey()));
		fs.add(getField(ADDITIONAL_RRS_NUMBER.getKey()));

		IField field = getField(QUESTIONS.getKey());
		if (field != null)
			fs.add(field);

		field = getField(ANSWER.getKey());
		if (field != null)
			fs.add(field);

		field = getField(AUTHORITY.getKey());
		if (field != null)
			fs.add(field);

		field = getField(ADDITIONAL_INFO.getKey());
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