package app.controllers;

import app.utilities.MainFunc;
import app.utilities.Utilities;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.bouncycastle.jce.provider.BrokenPBE;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.net.URL;
import java.util.ArrayList;
import java.util.ResourceBundle;

public class AppMainController implements Initializable {
    @FXML
    private Button logout;

    private FileChooser fileChooser = new FileChooser();
    @FXML
    private ListView<String> listViewFiles;
    @FXML
    private ListView<String> changesView;

    private String filename;
    public void userLogout(ActionEvent event) throws IOException {
        Main m = new Main();
        m.changeScene("log-in.fxml");
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        // Dohvati fajlove logovanog korisnika (metodom iz Utils)
        // Dohvati bilo kakve potencijalne izmjene

        ArrayList<String> currentFiles = MainFunc.listCurrentUserFiles(Utilities.getCurrentUser());
        ArrayList<String> changedFiles = MainFunc.changedFiles(Utilities.getCurrentUser());
        File file = new File("input" + File.separator + Utilities.getCurrentUser());
        fileChooser.setInitialDirectory(file);


            listViewFiles.getItems().addAll(currentFiles);
            changesView.getItems().addAll(changedFiles);
            listViewFiles.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<String>() {
                @Override
                public void changed(ObservableValue<? extends String> observableValue, String s, String t1) {
                    filename = listViewFiles.getSelectionModel().getSelectedItem();
                    try {
                        MainFunc.decryptFile(filename, Utilities.getCurrentUser());
                    } catch (Exception exception) {
                        exception.printStackTrace();
                    }
                }
            });

    }

    public void addFile(ActionEvent event) {
        File newFile = fileChooser.showOpenDialog(new Stage());
        try {
            if (newFile != null && !(MainFunc.existsInRepo(newFile))) {
                MainFunc.encryptFile(newFile, Utilities.getCurrentUser());
            }
            else{
                System.out.println("PODACI POSTOJE");
            }
        } catch (Exception e) {
            System.out.println("PROBLEM ADDDING FILE");
        }

    }

}


