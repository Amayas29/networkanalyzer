package fr.networkanalyzer.model;

import java.util.List;

import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.ILayerDataLink;

public class Frame {

	private ILayerDataLink message;

	public String getEncapsulatedProtocol() {
		return message.getEncapsulatedProtocol();
	}

	public void setLayerDataLink(ILayerDataLink message) {
		this.message = message;
	}

	public IField getFieldDataLink(String IField) {
		return message.getField(IField);
	}

	public IField getFieldNetwork(String IField) {
		return message.getIncluded().getField(IField);
	}

	public IField getFieldTransport(String IField) {
		return message.getIncluded().getIncluded().getField(IField);
	}

	public IField getFieldApplication(String IField) {
		return message.getIncluded().getIncluded().getIncluded().getField(IField);
	}

	public Integer getTotalLength() {
		return message.getTotalLength();
	}

	public List<IField> getFieldsDataLink() {
		return message.getFields();
	}

	public List<IField> getFieldsNetwork() {
		return message.getIncluded().getFields();
	}

	public List<IField> getFieldsTransport() {
		return message.getIncluded().getIncluded().getFields();
	}

	public List<IField> getFieldsApplication() {
		return message.getIncluded().getIncluded().getIncluded().getFields();
	}

}