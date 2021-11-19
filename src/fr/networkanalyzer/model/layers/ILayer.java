package fr.networkanalyzer.model.layers;

import java.util.List;

import fr.networkanalyzer.model.IField;

public interface ILayer {

	public List<IField> getFields();

	public IField getField(String field);

	public void addField(String name, IField field);

	public void accept(ILayerVisitor visitor);

	public String getEncapsulatedProtocol();

}
