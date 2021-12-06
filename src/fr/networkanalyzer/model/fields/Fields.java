package fr.networkanalyzer.model.fields;

import java.util.ArrayList;
import java.util.List;

public class Fields implements IField {

	private String name;

	private List<IField> fields;

	public Fields(String name) {
		this.name = name;
		fields = new ArrayList<>();
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getLength() {
		int sum = 0;

		for (IField f : fields)
			sum += f.getLength();

		return sum;
	}

	@Override
	public String getValue() {
		StringBuilder sb = new StringBuilder();

		int l = 0;
		for (IField f : fields) {
			l += f.getLength();
			sb.append(f.getValue());
		}

		l /= 4;

		int decimal = Integer.parseInt(sb.toString().replace(" ", ""), 2);
		String hex = Integer.toString(decimal, 16);
		l -= hex.length();

		for (int i = 0; i < l; i++)
			hex = "0" + hex;

		int n = hex.length();
		sb = new StringBuilder();
		for (int i = 0; i < n; i += 2) {
			sb.append(hex.charAt(i));
			sb.append(hex.charAt(i + 1));

			if (i != n - 2)
				sb.append(" ");
		}

		return sb.toString();
	}

	@Override
	public String getValueDecoded() {
		return "";
	}

	public void addField(IField f) {
		fields.add(f);
	}

	public IField getField(String name) {
		for (IField f : fields)
			if (f.getName().equals(name))
				return f;

		return null;
	}

	public List<IField> getChildrens() {
		return fields;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(getName());
		sb.append(" : \n");

		for (IField iField : getChildrens()) {
			sb.append("\t\t");
			sb.append(iField.toString());
			sb.append("\n");
		}

		String val = sb.toString();
		return val.substring(0, val.length() - 1);
	}

	public void removeField(String field) {
		fields.remove(getField(field));
	}

	@Override
	public String display() {
		return name;
	}
}
