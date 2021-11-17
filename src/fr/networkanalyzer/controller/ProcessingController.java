package fr.networkanalyzer.controller;

import fr.networkanalyzer.model.Analyzer;
import fr.networkanalyzer.model.Frame;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.SelectionMode;

public class ProcessingController {

	@SuppressWarnings("unused")
	private Analyzer analyzer;

	@FXML
	private ListView<Frame> framesList;

	@FXML
	public void initialize() {
		ObservableList<Frame> frames = FXCollections.observableArrayList(new Frame(), new Frame(), new Frame(),
				new Frame(), new Frame(), new Frame(), new Frame(), new Frame(), new Frame(), new Frame(), new Frame(),
				new Frame(), new Frame(), new Frame(), new Frame(), new Frame(), new Frame(), new Frame(), new Frame(),
				new Frame(), new Frame(), new Frame(), new Frame(), new Frame());
		framesList.setItems(frames);
		framesList.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);
	}

	public void setAnalyzer(Analyzer analyzer) {
		this.analyzer = analyzer;
	}

}