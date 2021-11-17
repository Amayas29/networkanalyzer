package fr.networkanalyzer.model.layers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import fr.networkanalyzer.model.Field;

public abstract class AbstractLayer implements Layer {

	private Map<String, Field> fields;

	public AbstractLayer() {
		fields = new HashMap<>();
	}

	@Override
	public List<Field> getFields() {
		return new ArrayList<>(fields.values());
	}

	@Override
	public Field getField(String field) {
		return fields.get(field);
	}

	@Override
	public void addField(String name, Field field) {
		fields.put(name, field);
	}

}