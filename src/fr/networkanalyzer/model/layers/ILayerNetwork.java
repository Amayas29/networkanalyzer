package fr.networkanalyzer.model.layers;

public interface ILayerNetwork extends ILayer {

	public Integer getTotalLength();

	public default ILayerTransport getIncluded() {
		throw new UnsupportedOperationException();
	}

	public default void setIncluded(ILayerTransport layer) {
		throw new UnsupportedOperationException();
	}
}