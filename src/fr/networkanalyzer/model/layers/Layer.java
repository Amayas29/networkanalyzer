package fr.networkanalyzer.model.layers;

import java.io.BufferedReader;
import java.util.List;

import fr.networkanalyzer.model.Field;

public interface Layer {

	public List<Field> getFields();

	public Field getField(String field);

	public void addField(String name, Field field);

	public void parse(BufferedReader in);
}
