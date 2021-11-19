package fr.networkanalyzer.model.layers;

public interface ILayerDataLink extends ILayer {

	public Integer getTotalLength();

	public ILayerNetwork getIncluded();

	public void setIncluded(ILayerNetwork layer);
}