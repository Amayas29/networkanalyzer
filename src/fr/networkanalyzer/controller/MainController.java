package fr.networkanalyzer.controller;

import java.io.File;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.stage.FileChooser;

public class MainController {

	@FXML
	private Button loadBtn;

	@FXML
	private Button chooseBtn;

	@FXML
	private Label infoLabel;

	@FXML
	private TextField filenameInput;

	@FXML
	public void initialize() {
		loadBtn.setDefaultButton(true);
	}

	@FXML
	public void loadFile(ActionEvent event) {
		String filename = filenameInput.getText();
		File file = new File(filename);
		checkFile(file);
	}

	@FXML
	public void chooseFile(ActionEvent event) {

		Scene scene = chooseBtn.getScene();
		FileChooser fileChooser = new FileChooser();
		
//		FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("TXT files (*.txt)", "*.txt");
//		fileChooser.getExtensionFilters().add(extFilter);
		
		File file = fileChooser.showOpenDialog(scene.getWindow());

		checkFile(file);
	}

	@FXML
	void keyReleased(KeyEvent event) {
		if (event.getCode() == KeyCode.ENTER)
			return;

		infoLabel.setText("");
		infoLabel.setVisible(false);
	}

	private boolean checkFile(File file) {
		if (file == null || !file.exists()) {
			infoLabel.setText("The file does not exist.");
			infoLabel.setVisible(true);
			return false;
		}

		if (!file.isFile()) {
			infoLabel.setText("The node is not a file.");
			infoLabel.setVisible(true);
			return false;
		}

		if (!file.canRead()) {
			infoLabel.setText("The file is in 'cannot read' mode.");
			infoLabel.setVisible(true);
			return false;
		}
		
		return true;
	}
}