package fr.networkanalyzer.controller;

import fr.networkanalyzer.model.Analyzer;
import javafx.fxml.FXML;

public class ProcessingController {

	private static Analyzer analyzer;

	@FXML
	public void initialize() {
		// TODO Auto-generated method stub
		
	}

	public static void setAnalyzer(Analyzer analyzer) {
		ProcessingController.analyzer = analyzer;
	}

}
