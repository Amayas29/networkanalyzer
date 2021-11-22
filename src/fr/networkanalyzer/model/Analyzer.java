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

}
