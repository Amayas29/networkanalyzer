package fr.networkanalyzer.controller;

import java.io.File;
import java.io.IOException;

import fr.networkanalyzer.model.Analyzer;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import javafx.animation.Animation;
import javafx.animation.PauseTransition;
import javafx.animation.RotateTransition;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.layout.Pane;
import javafx.scene.shape.Circle;
import javafx.scene.text.TextAlignment;
import javafx.stage.Stage;
import javafx.util.Duration;

public class LoadingController {

	private static final int SLEEP_TIME = 3;

	@FXML
	private Pane errorsPane;

	@FXML
	private Label errorsLabel;

	@FXML
	private Circle topCircle;

	@FXML
	private Circle meduimCircle;

	@FXML
	private Circle bottomCircle;

	private File file;

	private RotateTransition rt;

	public LoadingController(File file) {
		this.file = file;
	}

	@FXML
	public void initialize() {

		errorsPane.setVisible(false);
		setRotate(topCircle, 360, 10);
		setRotate(meduimCircle, 180, 18);
		setRotate(bottomCircle, 145, 20);

		ParseService ps = new ParseService(file);
		ps.setOnSucceeded(wse -> {

			PauseTransition pause = new PauseTransition(Duration.seconds(SLEEP_TIME));

			pause.setOnFinished(event -> {
				Analyzer analyzer = ps.getValue();
				try {
					throwProcessingStage(analyzer);
				} catch (NetworkAnalyzerException e) {
					displayError(e.getMessage());
				}
			});
			pause.play();

		});

		ps.setOnFailed(wse -> {

			PauseTransition pause = new PauseTransition(Duration.seconds(SLEEP_TIME));
			pause.setOnFinished(event -> {
				displayError(ps.getException().getMessage());
			});
			pause.play();

		});

		ps.start();
	}

	@FXML
	public void exitApp() {
		System.exit(0);
	}

	@FXML
	public void returnToPrincipalPage(ActionEvent event) {

		Stage stage = (Stage) errorsLabel.getScene().getWindow();
		Parent root = null;

		try {
			root = FXMLLoader.load(getClass().getResource("/fr/networkanalyzer/view/fxml/main.fxml"));
		} catch (IOException e) {
			displayError("Ressource can't be loaded");
			return;
		}

		Scene scene = new Scene(root);
		stage.setScene(scene);
	}

	private void throwProcessingStage(Analyzer analyzer) throws NetworkAnalyzerException {

		Stage stage = (Stage) errorsLabel.getScene().getWindow();

		FXMLLoader loader = new FXMLLoader(getClass().getResource("/fr/networkanalyzer/view/fxml/processing.fxml"));
		ProcessingController pc = new ProcessingController(analyzer);

		loader.setController(pc);

		Parent root = null;
		try {
			root = loader.load();
		} catch (IOException e) {
			throw new NetworkAnalyzerException("Ressource can't be loaded");
		}

		Scene scene = new Scene(root);
		stage.setScene(scene);
	}

	private void displayError(String errorMessage) {
		errorsPane.setVisible(true);
		errorsLabel.setVisible(true);
		errorsLabel.setAlignment(Pos.CENTER);
		errorsLabel.setTextAlignment(TextAlignment.CENTER);
		errorsLabel.setText(errorMessage);
	}

	private void setRotate(Circle c, int angle, int duration) {
		rt = new RotateTransition(Duration.seconds(duration), c);
		rt.setAutoReverse(true);
		rt.setByAngle(angle);
		rt.setDelay(Duration.seconds(0));
		rt.setRate(5);
		rt.setCycleCount(Animation.INDEFINITE);
		rt.play();
	}
}