package fr.networkanalyzer.model.fields;

import java.util.List;

public class Field implements IField {

	private String name;
	private String value;
	private String valueDecoded;
	private String content;
	private int length;
	private boolean isFlag;

	public Field(Entry<String, Integer> entry, String value, String valueDecoded) {
		this.name = entry.getKey();
		this.value = value;
		this.valueDecoded = valueDecoded;
		this.length = entry.getValue();
		content = value;
		isFlag = false;
	}

	public Field(Entry<String, Integer> entry, String value, String valueDecoded, boolean isFlag) {
		this(entry, value, valueDecoded);
		this.isFlag = isFlag;
	}

	public Field(Entry<String, Integer> entry, String value, String valueDecoded, String content) {
		this(entry, value, valueDecoded);
		this.content = content;
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
		return String.format("%s : %s (%s) | %d bits", name, content, valueDecoded, length);
	}

	@Override
	public List<IField> getChildrens() {
		return null;
	}

	@Override
	public String display() {
		return toString();
	}

	@Override
	public boolean isOptions() {
		return false;
	}

	@Override
	public boolean isFlag() {
		return isFlag;
	}

}