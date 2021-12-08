package fr.networkanalyzer.model;

import java.util.ArrayList;
import java.util.List;

public class Analyzer {

	private List<Frame> frames;
	private List<String> errors;

	public Analyzer() {
		frames = new ArrayList<>();
		errors = new ArrayList<>();
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

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("correct frames :\n");
		sb.append(String.format("\t\t %4s \t %30s \t %30s \t %10s \t %10s \n","N°","IP SOURCE","IP DESTINATION","PROTOCOL","LENGTH"));
		for (Frame f : frames) {
			sb.append(f.toString()).append("\n");
		}

		sb.append(" Errors :\n");

		for (String string : errors)
			sb.append(string).append("\n");

		if (errors.isEmpty())
			sb.append("\t\tEmpty");

		return sb.toString();
	}

}
