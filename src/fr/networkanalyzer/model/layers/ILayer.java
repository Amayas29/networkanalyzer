package fr.networkanalyzer.model.layers;

import java.util.List;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public interface ILayer {

	public List<IField> getFields();

	public IField getField(String field);

	public void addField(String name, IField field);

	public void accept(ILayerVisitor visitor) throws NetworkAnalyzerException;

	public String getEncapsulatedProtocol();

	public String getName();

	public int getLength();
}
