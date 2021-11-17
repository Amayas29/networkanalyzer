package fr.networkanalyzer.model;

import java.util.List;

import fr.networkanalyzer.model.layers.LayerDataLink;

public class Frame {

	private LayerDataLink message;

	public void setLayerDataLink(LayerDataLink message) {
		this.message = message;
	}

	public Field getFieldDataLink(String field) {
		return message.getField(field);
	}

	public Field getFieldNetwork(String field) {
		return message.getIncluded().getField(field);
	}

	public Field getFieldTransport(String field) {
		return message.getIncluded().getIncluded().getField(field);
	}

	public Field getFieldApplication(String field) {
		return message.getIncluded().getIncluded().getIncluded().getField(field);
	}

	public Integer getTotalLength() {
		return message.getTotalLength();
	}

	public List<Field> getFieldsDataLink() {
		return message.getFields();
	}

	public List<Field> getFieldsNetwork() {
		return message.getIncluded().getFields();
	}

	public List<Field> getFieldsTransport() {
		return message.getIncluded().getIncluded().getFields();
	}

	public List<Field> getFieldsApplication() {
		return message.getIncluded().getIncluded().getIncluded().getFields();
	}

}