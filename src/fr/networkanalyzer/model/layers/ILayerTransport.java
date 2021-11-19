package fr.networkanalyzer.model.layers;

public interface ILayerTransport extends ILayer {

	public default ILayerApplication getIncluded() {
		throw new UnsupportedOperationException();
	}

	public default void setIncluded(ILayerApplication layer) {
		throw new UnsupportedOperationException();
	}
}