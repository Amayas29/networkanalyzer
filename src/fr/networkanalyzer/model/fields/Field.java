package fr.networkanalyzer.model.fields;

import java.util.List;

public class Field implements IField {

	private String name;
	private String value;
	private String valueDecoded;
	private String content;
	private int length;

	public Field(Entry entry, String value, String valueDecoded) {
		this.name = entry.getName();
		this.value = value;
		this.valueDecoded = valueDecoded;
		this.length = entry.getValue();
		content = value;
	}

	public Field(Entry entry, String value, String valueDecoded, boolean hasContent) {
		this(entry, value, valueDecoded);

		if (!hasContent)
			content = "";
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
	public boolean isOption() {
		// TODO Auto-generated method stub
		return false;
	}

	

}