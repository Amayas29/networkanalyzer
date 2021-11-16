package fr.networkanalyzer.model.exceptions;

public class NetworkAnalyzerNullPointerException extends NetworkAnalyzerException {

	private static final long serialVersionUID = 1L;

	public NetworkAnalyzerNullPointerException() {
		super("Pointer is null");
	}

}