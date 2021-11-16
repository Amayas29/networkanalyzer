package fr.networkanalyzer.controller;

import java.io.File;
import java.io.IOException;

import fr.networkanalyzer.model.Analyzer;
import fr.networkanalyzer.model.AnalyzerParserRunnable;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerNullPointerException;
import javafx.animation.Animation;
import javafx.animation.RotateTransition;
import javafx.concurrent.WorkerStateEvent;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.layout.Pane;
import javafx.scene.shape.Circle;
import javafx.scene.text.TextAlignment;
import javafx.stage.Stage;
import javafx.util.Duration;

public class LoadingController {

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

	private static File file;

	private RotateTransition rt;

	public static void setFile(File f) {
		file = f;
	}

	@FXML
	public void initialize() {

		errorsPane.setVisible(false);
		setRotate(topCircle, 360, 10);
		setRotate(meduimCircle, 180, 18);
		setRotate(bottomCircle, 145, 20);

//		ParseService ps = new ParseService(file);
//		ps.setOnSucceeded(new EventHandler<WorkerStateEvent>() {
//
//			@Override
//			public void handle(WorkerStateEvent wse) {
//				errorsPane.setVisible(true);
//				errorsLabel.setText("Succes");
//				
//			}
//		});
//
//		ps.setOnFailed(new EventHandler<WorkerStateEvent>() {
//
//			@Override
//			public void handle(WorkerStateEvent wse) {
//				errorsPane.setVisible(true);
//				errorsLabel.setText("Failed");
//			}
//		});
//
//		ps.start();

		AnalyzerParserRunnable analyzerParserRunnable = new AnalyzerParserRunnable(file,this);
		Thread analyzerThread = new Thread(analyzerParserRunnable);
		analyzerThread.start();

	
//		try {
//			Thread.sleep(5000);
//		} catch (InterruptedException e) {
//			e.printStackTrace();
//		}
//		if (analyzerParserRunnable.getMessage() != null) {
//			signalError(analyzerParserRunnable.getMessage());
//			return;
//		}
//		try {
//			throwLoadingStage(analyzerParserRunnable.getAnalyzer());
//		} catch (IOException e) {
//			e.printStackTrace();
//		} catch (NetworkAnalyzerNullPointerException e) {
//			signalError(e.getMessage());
//
//		}

	}

	@FXML
	public void exitApp(ActionEvent event) {
		System.exit(0);
	}

	@FXML
	public void returnToPrincipalPage(ActionEvent event) {

		Stage stage = (Stage) errorsLabel.getScene().getWindow();
		Parent root = null;
		try {
			root = FXMLLoader.load(getClass().getResource("/fr/networkanalyzer/view/fxml/main.fxml"));
		} catch (IOException e) {
			e.printStackTrace();
		}
		Scene scene = new Scene(root);
		stage.setScene(scene);
	}

	public void throwLoadingStage(Analyzer analyzer) throws IOException, NetworkAnalyzerNullPointerException {
		if (analyzer == null)
			throw new NetworkAnalyzerNullPointerException();
		ProcessingController.setAnalyzer(analyzer);

		Stage stage = (Stage) errorsLabel.getScene().getWindow();
		Parent root = FXMLLoader.load(getClass().getResource("/fr/networkanalyzer/view/fxml/processing.fxml"));
		Scene scene = new Scene(root);
		stage.setScene(scene);
	}

	public void signalError(String errorMessage) {
		errorsPane.setVisible(true);
		errorMessage = String.format("%" + (130 - errorMessage.length()) + "s", " ") + errorMessage
				+ String.format("%" + (130 - errorMessage.length()) + "s", " ");

		System.out.println(errorMessage);
		errorsLabel.setText(errorMessage);
		errorsLabel.setTextAlignment(TextAlignment.CENTER);
		errorsLabel.setWrapText(true);

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
