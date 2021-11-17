package fr.networkanalyzer.model.layers;

public interface LayerTransport extends Layer {

	public default LayerApplication getIncluded() {
		throw new UnsupportedOperationException();
	}
}
