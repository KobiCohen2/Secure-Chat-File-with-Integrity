package com.kinneret.scafti.ui;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;

public class Main extends Application {

    public static Controller controller;

    @Override
    public void start(Stage primaryStage) throws Exception{
        FXMLLoader fxmlLoader = new FXMLLoader();
        Pane pane = fxmlLoader.load(getClass().getResource("SCAFTI.fxml").openStream());
        controller = fxmlLoader.getController();
        primaryStage.setTitle("SCAFTI");
        primaryStage.setScene(new Scene(pane, 1200, 650));
        primaryStage.setResizable(false);
        primaryStage.show();
    }


    public static void main(String[] args) {
        launch(args);
    }
}
