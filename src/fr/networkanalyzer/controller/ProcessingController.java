package fr.networkanalyzer.controller;

import fr.networkanalyzer.model.Analyzer;
import fr.networkanalyzer.model.Frame;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.SelectionMode;
import javafx.scene.control.TreeView;
import javafx.scene.layout.VBox;

public class ProcessingController {


    @FXML
    private TreeView<?> rootTree;

    @FXML
    private VBox tramVb;
    
	private Analyzer analyzer;

	public ProcessingController(Analyzer analyzer) {
		this.analyzer = analyzer;
	}

	@FXML
	public void initialize() {
	
	}

}