package fr.networkanalyzer.model.fields;

public class Entry<k, v> {

	private final k key;
	private v value;

	public Entry(k key, v length) {
		this.key = key;
		value = length;
	}

	public v getValue() {
		return value;
	}

	public void setValue(v value) {
		this.value = value;
	}

	public k getKey() {
		return key;
	}
}
