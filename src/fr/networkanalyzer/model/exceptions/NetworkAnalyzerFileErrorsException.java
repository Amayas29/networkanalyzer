package fr.networkanalyzer.model.exceptions;

public class NetworkAnalyzerFileErrorsException extends NetworkAnalyzerException {

	private static final long serialVersionUID = 1L;
	private String message;
	public NetworkAnalyzerFileErrorsException(String message) {
		this.message = message; 
		// TODO Auto-generated constructor stub
	}
	@Override
	public String getMessage() {
		// TODO Auto-generated method stub
		return message;
	}

}
