package fr.networkanalyzer.model;

import java.util.ArrayList;
import java.util.List;

public class Analyzer {

	private List<Frame> frames;

	public Analyzer() {
		frames = new ArrayList<>();
	}

	public void addFrame(Frame frame) {
		frames.add(frame);
	}

	public List<Frame> getFrames() {
		return frames;
	}

}
