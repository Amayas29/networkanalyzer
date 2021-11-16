package fr.networkanalyzer.model.exceptions;

public class NetworkAnalyzerException extends Exception {

	
	private static final long serialVersionUID = 1L;

	public NetworkAnalyzerException() {
		super();
	}

	public NetworkAnalyzerException(String message) {
		super("Network Analyzer Exception | " + message );
	
	}

}
