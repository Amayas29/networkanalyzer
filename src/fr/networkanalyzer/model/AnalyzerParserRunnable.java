package fr.networkanalyzer.model;

import java.io.File;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;

public class AnalyzerParserRunnable implements Runnable {
	
	private File file;
	private String message;
	private Analyzer analyzer;
	public AnalyzerParserRunnable(File file) {
		this.file = file;
		message = null;
		analyzer = null;
	}


	@Override
	public void run() {
		
		try {
			
			analyzer = AnalyzerParser.parse(file);
			
		} catch (NetworkAnalyzerException e) {
			message = e.getMessage();
			
		}
	}
	
	public Analyzer getAnalyzer() {
		return analyzer;
	}
	
	public String getMessage() {
		return message;
	}
	
	
	public File getFile() {
		return file;
	}
	

}
