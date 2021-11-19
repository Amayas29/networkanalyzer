package fr.networkanalyzer.model;

import java.util.List;

public interface IField {

	public String getName();

	public int getLength();

	public String getValue();

	public String getValueDecoded();

	public List<IField> getChildrens();

}
