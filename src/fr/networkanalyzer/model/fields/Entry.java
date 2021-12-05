package fr.networkanalyzer.model.fields;

public class Entry {

	private final String name;
	private int value;
	

	public Entry(String name, int length) {
		this.name = name;
		value = length;	
	}
	public int getValue() {
		return value;
	}
	
	public void setValue(int value) {
		this.value = value;
	}
	public String getName() {
		return name;
	}
}
