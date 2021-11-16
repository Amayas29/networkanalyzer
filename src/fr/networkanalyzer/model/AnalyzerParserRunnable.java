package fr.networkanalyzer.model;

import java.io.File;
import java.io.IOException;

import fr.networkanalyzer.controller.LoadingController;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;

public class AnalyzerParserRunnable implements Runnable {
	
	private File file;
	private String message;
	private Analyzer analyzer;
	private LoadingController loadingController;
	public AnalyzerParserRunnable(File file, LoadingController loadingController) {
		this.file = file;
		message = null;
		analyzer = null;
		this.loadingController = loadingController;
	}


	@Override
	public void run() {
		
		try {
			
			analyzer = AnalyzerParser.parse(file);
//			try {
//				Thread.sleep(2000);
//			} catch (InterruptedException e) {
//			}
			
			loadingController.throwLoadingStage(analyzer);
		} catch (NetworkAnalyzerException e) {
			loadingController.signalError(e.getMessage());
			
		}catch (Exception e) {
			// TODO: handle exception
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
