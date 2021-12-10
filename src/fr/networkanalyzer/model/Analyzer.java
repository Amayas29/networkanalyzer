package fr.networkanalyzer.model;

import java.util.ArrayList;
import java.util.List;

import fr.networkanalyzer.model.layers.protocols.Ip;

public class Analyzer {

	private List<Frame> frames;
	private List<String> errors;
	private List<String> warnings;

	public Analyzer() {
		frames = new ArrayList<>();
		errors = new ArrayList<>();
		warnings = new ArrayList<>();
	}

	public void addFrame(Frame frame) {
		frames.add(frame);
	}

	public List<Frame> getFrames() {
		return frames;
	}

	public void addError(String error) {
		errors.add(error);
	}

	public List<String> getErrors() {
		return errors;
	}

	public void addWarning(String s) {
		warnings.add(s);
	}

	public List<String> getWarnings() {
		return warnings;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("correct frames :\n");
		String s = "\t\t %-4s \t %-30s \t %-30s \t %-15s \t %-10s \n";
		sb.append(String.format(s, "N°", "IP SOURCE", "IP DESTINATION", "PROTOCOL", "LENGTH"));

		for (Frame f : frames)
			sb.append(String.format(s, f.getId(), f.getFieldNetwork(Ip.SRC_ADDRESS.getKey()).getValueDecoded(),
					f.getFieldNetwork(Ip.DEST_ADDRESS.getKey()).getValueDecoded(), f.getEncapsulatedProtocol(),
					String.valueOf(f.getTotalLength())));

		sb.append(" Warnings :\n\t\t");

		for (String string : getWarnings()) {
			sb.append(string).append("\n\t\t");
		}

		if (warnings.isEmpty())
			sb.append("\t\tEmpty");
		sb.append("\n");
		sb.append(" Errors :\n");

		for (String string : getErrors())
			sb.append("\t\t").append(string).append("\n");

		if (errors.isEmpty())
			sb.append("\t\tEmpty");

		return sb.toString();
	}

}
