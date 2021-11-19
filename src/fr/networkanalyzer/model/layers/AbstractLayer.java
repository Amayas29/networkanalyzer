package fr.networkanalyzer.model.layers;

import java.util.HashMap;
import java.util.Map;

import fr.networkanalyzer.model.IField;

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

}