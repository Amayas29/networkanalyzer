package fr.networkanalyzer.application;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

public class Main extends Application {
	@Override
	public void start(Stage stage) {
		try {
			stage.setTitle("networkanalyzer");
			Parent root = FXMLLoader.load(getClass().getResource("/fr/networkanalyzer/view/fxml/processing.fxml"));
			Scene scene = new Scene(root);
			stage.setScene(scene);
			stage.setResizable(false);

			stage.getIcons().add(new Image(getClass().getResource("app_icon.jpg").toURI().toString()));

			stage.show();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		launch(args);
	}
}
