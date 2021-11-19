package fr.networkanalyzer.model.layers.protocols;

import java.util.List;

import fr.networkanalyzer.model.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerNetwork;
import fr.networkanalyzer.model.layers.ILayerVisitor;

public class Arp extends AbstractLayer implements ILayerNetwork {

	private static final int LENGTH = 28;

	@Override
	public void accept(ILayerVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public Integer getTotalLength() {
		return LENGTH;
	}

	@Override
	public List<IField> getFields() {
		return null;
	}

	@Override
	public String getEncapsulatedProtocol() {
		return "ARP";
	}

}