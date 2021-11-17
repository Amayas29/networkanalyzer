package fr.networkanalyzer.model;

public class Field {

	private String name;
	private String value;
	private String valueDecoded;
	private int length;

	public Field(String name, String value, String valueDecoded, int length) {
		this.name = name;
		this.value = value;
		this.valueDecoded = valueDecoded;
		this.length = length;
	}

	public String getName() {
		return name;
	}

	public int getLength() {
		return length;
	}

	public String getValue() {
		return value;
	}

	public String getValueDecoded() {
		return valueDecoded;
	}

}