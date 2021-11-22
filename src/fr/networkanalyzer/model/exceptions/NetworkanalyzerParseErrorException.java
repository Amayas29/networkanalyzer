package fr.networkanalyzer.model.exceptions;

public class NetworkanalyzerParseErrorException extends NetworkAnalyzerException {

	private static final long serialVersionUID = 1L;

	public NetworkanalyzerParseErrorException(int line, String errorMessage) {
		super(String.format("Error on line [%d] : %s", line, errorMessage));
	}

	public NetworkanalyzerParseErrorException() {
		super("Empty frame");
	}

}
