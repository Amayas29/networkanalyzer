package fr.networkanalyzer.controller;

import java.io.File;

import fr.networkanalyzer.model.Analyzer;
import javafx.concurrent.Service;
import javafx.concurrent.Task;

public class ParseService extends Service<Analyzer> {

	private File file;
	private ParseTask parseTask;
	private String message;
	
	public ParseService(File file) {
		this.file = file;
	}
	
	@Override
	protected Task<Analyzer> createTask() {
		parseTask = new ParseTask(file);
		message = parseTask.getMessage();
		return parseTask;
	}
	
	public String getMessageError() {
		return message;
	}
	
	public Analyzer getAnalyzer() {
		return parseTask.getAnalyzer();
	}


}
