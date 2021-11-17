package fr.networkanalyzer.controller;

import java.io.File;
import java.io.IOException;

import fr.networkanalyzer.model.AnalyzerParser;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.effect.DropShadow;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

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

		if (!checkFile(file))
			return;

		try {
			throwLoadingStage(file);
		} catch (NetworkAnalyzerException e) {
			infoLabel.setText(e.getMessage());
			infoLabel.setVisible(true);
		}
	}

	@FXML
	public void chooseFile(ActionEvent event) {

		Scene scene = chooseBtn.getScene();
		FileChooser fileChooser = new FileChooser();

		File file = fileChooser.showOpenDialog(scene.getWindow());

		if (!checkFile(file))
			return;

		try {
			throwLoadingStage(file);
		} catch (NetworkAnalyzerException e) {
			infoLabel.setText(e.getMessage());
			infoLabel.setVisible(true);
		}
	}

	@FXML
	void keyReleased(KeyEvent event) {
		if (event.getCode() == KeyCode.ENTER)
			return;

		infoLabel.setText("");
		infoLabel.setVisible(false);
	}

	private boolean checkFile(File file) {
		try {
			AnalyzerParser.verifyFile(file);
		} catch (NetworkAnalyzerException e) {
			infoLabel.setText(e.getMessage());
			infoLabel.setVisible(true);
			return false;
		}

		return true;
	}

	private void throwLoadingStage(File file) throws NetworkAnalyzerException {

		Stage stage = (Stage) loadBtn.getScene().getWindow();

		FXMLLoader loader = new FXMLLoader(getClass().getResource("/fr/networkanalyzer/view/fxml/loading.fxml"));
		LoadingController lc = new LoadingController();
		lc.setFile(file);
		loader.setController(lc);

		Parent root = null;
		try {
			root = loader.load();
		} catch (IOException e) {
			throw new NetworkAnalyzerException("Ressource can't be loaded");
		}

		Scene scene = new Scene(root);
		stage.setScene(scene);
	}

	@FXML
	public void hoverButton(MouseEvent event) {
		DropShadow e = new DropShadow();
		e.setWidth(10);
		e.setHeight(10);
		e.setOffsetX(10);
		e.setOffsetY(10);
		e.setRadius(10);
		loadBtn.setEffect(e);
	}

}