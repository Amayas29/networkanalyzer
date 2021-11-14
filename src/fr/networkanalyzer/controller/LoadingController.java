package fr.networkanalyzer.controller;

import javafx.animation.Animation;
import javafx.animation.RotateTransition;
import javafx.fxml.FXML;
import javafx.scene.shape.Circle;
import javafx.util.Duration;

public class LoadingController {
	
	@FXML
	private Circle topCircle;
	
	@FXML
	private Circle meduimCircle;
	
	@FXML
	private Circle bottomCircle;

	@FXML
	public void initialize() {
		setRotate(topCircle, 360, 10);
		setRotate(meduimCircle, 180, 18);
		setRotate(bottomCircle, 145, 20);
	}

	private void setRotate(Circle c, int angle, int duration) {
		RotateTransition rt = new RotateTransition(Duration.seconds(duration), c);
		rt.setAutoReverse(true);
		rt.setByAngle(angle);
		rt.setDelay(Duration.seconds(0));
		rt.setRate(5);
		rt.setCycleCount(Animation.INDEFINITE);
		rt.play();
	}
	
}
