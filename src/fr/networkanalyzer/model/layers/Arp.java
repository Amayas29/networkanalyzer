package fr.networkanalyzer.model.layers;

import java.io.BufferedReader;

public class Arp extends AbstractLayer implements LayerNetwork {

	private static final int LENGTH = 28;

	@Override
	public void parse(BufferedReader in) {

	}

	@Override
	public Integer getTotalLength() {
		return LENGTH;
	}

}