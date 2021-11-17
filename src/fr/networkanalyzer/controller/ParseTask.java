package fr.networkanalyzer.controller;

import java.io.File;

import fr.networkanalyzer.model.Analyzer;
import fr.networkanalyzer.model.AnalyzerParser;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import javafx.concurrent.Task;

public class ParseTask extends Task<Analyzer> {

	private File file;

	public ParseTask(File file) {
		this.file = file;
	}

	@Override
	protected Analyzer call() throws NetworkAnalyzerException {
		return AnalyzerParser.parse(file);
	}

}