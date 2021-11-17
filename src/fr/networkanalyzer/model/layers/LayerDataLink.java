package fr.networkanalyzer.model.layers;

public interface LayerDataLink extends Layer {

	public Integer getTotalLength();

	public LayerNetwork getIncluded();
}