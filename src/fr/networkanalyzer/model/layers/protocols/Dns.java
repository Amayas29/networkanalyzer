package fr.networkanalyzer.model.layers.protocols;

import java.util.List;

import fr.networkanalyzer.model.fields.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerApplication;
import fr.networkanalyzer.model.visitors.ILayerVisitor;

public class Dns extends AbstractLayer implements ILayerApplication {

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
		return "DNS";
	}

}