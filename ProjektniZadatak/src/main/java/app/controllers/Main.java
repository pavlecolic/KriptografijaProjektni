package app.controllers;

import javafx.application.Application;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class Main extends Application {
    private static Stage stage;

    @Override
    public void start(Stage primaryStage) throws IOException {
        stage = primaryStage;
        primaryStage.setResizable(false);
        Parent root =  FXMLLoader.load(getClass().getResource("cert_form.fxml"));
        Scene scene = new Scene(root, 600, 400);
        primaryStage.setTitle("SafeRepo");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public void changeScene(String fxml) throws IOException {
        Parent pane = FXMLLoader.load(getClass().getResource(fxml));
        stage.setResizable(true);
        stage.getScene().setRoot(pane);
    }

//    public void changeSceneToLogin(String username) {
//        try {
//            Parent pane = FXMLLoader.load(getClass().getResource("log-in.fxml"));
//            stage.setResizable(true);
//            stage.getScene().setRoot(pane);
//        }
//        catch (IOException e){
//            e.printStackTrace();
//        }
//    }



    public static void main(String[] args) {
        launch();
    }
}