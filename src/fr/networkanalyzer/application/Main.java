package fr.networkanalyzer.application;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {
	@Override
	public void start(Stage primaryStage) {
		try {
			primaryStage.setTitle("networkanalyzer");
			Parent root = FXMLLoader.load(getClass().getResource("/fr/networkanalyzer/view/fxml/main.fxml"));

			Scene scene = new Scene(root);
			primaryStage.setScene(scene);
			primaryStage.setResizable(false);
			// /networkanalyzer/src/fr/networkanalyzer/application/Main.java
//			primaryStage.getIcons().add(new Image(getClass().getResource("app_icon.jpg").toURI().toString()));

			primaryStage.show();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		launch(args);
	}
}
