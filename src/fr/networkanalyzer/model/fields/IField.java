package fr.networkanalyzer.model.fields;

import java.util.List;

public interface IField {

	public String getName();

	public int getLength();

	public String getValue();

	public String getValueDecoded();

	public List<IField> getChildrens();

	public String display();

	public boolean isOptions();
	
	public boolean isFlag();
}
