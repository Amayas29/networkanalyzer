package fr.networkanalyzer.model.layers;

import java.util.HashMap;
import java.util.Map;

import fr.networkanalyzer.model.fields.IField;

public abstract class AbstractLayer implements ILayer {

	protected Map<String, IField> fields;

	public AbstractLayer() {
		fields = new HashMap<>();
	}

	@Override
	public IField getField(String field) {
		return fields.get(field);
	}

	@Override
	public void addField(String name, IField field) {
		fields.put(name, field);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(getName());
		sb.append("\n");

		for (IField field : getFields()) {
			sb.append("\t");
			sb.append(field.toString());
			sb.append("\n");
		}

		sb.append("\n\n");

		return sb.toString();
	}

	@Override
	public int getLength() {
		int len = 0;

		for (IField field : fields.values())
			len += field.getLength();

		return len;
	}
}