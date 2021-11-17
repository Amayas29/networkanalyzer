package fr.networkanalyzer.controller;

import java.io.File;

import fr.networkanalyzer.model.Analyzer;
import javafx.concurrent.Service;
import javafx.concurrent.Task;

public class ParseService extends Service<Analyzer> {

	private File file;

	public ParseService(File file) {
		this.file = file;
	}

	@Override
	protected Task<Analyzer> createTask() {
		return new ParseTask(file);
	}

}
