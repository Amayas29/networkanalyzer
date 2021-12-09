package fr.networkanalyzer.model.exceptions;

public class NetworkanalyzerParseWarningException extends NetworkanalyzerParseErrorException {

	private static final long serialVersionUID = 1L;

	public NetworkanalyzerParseWarningException(int len, String message) {
		super(len, message);
	}
}
