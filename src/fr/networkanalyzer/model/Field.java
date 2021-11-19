package fr.networkanalyzer.model;

import java.util.List;

public class Field implements IField {

	private String name;
	private String value;
	private String valueDecoded;
	private int length;

	public Field(Entry entry, String value, String valueDecoded) {
		this.name = entry.NAME;
		this.value = value;
		this.valueDecoded = valueDecoded;
		this.length = entry.LENGTH;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getLength() {
		return length;
	}

	@Override
	public String getValue() {
		return value;
	}

	@Override
	public String getValueDecoded() {
		return valueDecoded;
	}

	@Override
	public String toString() {
		return String.format("%s : %s (%s) | %d bits", name, value, valueDecoded, length);
	}

	@Override
	public List<IField> getChildrens() {
		return null;
	}

}