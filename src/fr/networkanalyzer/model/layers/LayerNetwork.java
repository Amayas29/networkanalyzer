package fr.networkanalyzer.model.layers;

public interface LayerNetwork extends Layer {

	public Integer getTotalLength();

	public default LayerTransport getIncluded() {
		throw new UnsupportedOperationException();
	}
}