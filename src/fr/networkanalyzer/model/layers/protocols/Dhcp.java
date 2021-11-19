package fr.networkanalyzer.model.layers.protocols;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.IField;
import fr.networkanalyzer.model.layers.AbstractLayer;
import fr.networkanalyzer.model.layers.ILayerApplication;
import fr.networkanalyzer.model.layers.ILayerVisitor;

public class Dhcp extends AbstractLayer implements ILayerApplication {

	@Override
	public void accept(ILayerVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public List<IField> getFields() {
		return new ArrayList<>();
	}

	@Override
	public String getEncapsulatedProtocol() {
		return "DHCP";
	}
}