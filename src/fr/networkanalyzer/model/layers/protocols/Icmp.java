package fr.networkanalyzer.model.layers.protocols;

import java.util.List;

import fr.networkanalyzer.model.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerTransport;
import fr.networkanalyzer.model.layers.ILayerVisitor;

public class Icmp extends AbstractLayer implements ILayerTransport {

	@Override
	public void accept(ILayerVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public List<IField> getFields() {
		return null;
	}

	@Override
	public String getEncapsulatedProtocol() {
		return "ICMP";
	}

}