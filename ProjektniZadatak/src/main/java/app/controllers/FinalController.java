package app.controllers;

import app.utilities.Cryptography;
import app.utilities.Utilities;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

import java.io.IOException;

public class FinalController {
@FXML
    private TextField usernameField;
@FXML
    private PasswordField passwordField;
@FXML
    private Button retreiveButton;

    @FXML
    private void tryRetreive(ActionEvent e) throws IOException {
        Main m = new Main();

        if(Utilities.validateLogin(usernameField.getText(), passwordField.getText())) {
            Cryptography.removeFromCRL();
            m.changeScene("cert_form.fxml");
        }
        else {
           m.changeScene("cert_form.fxml");
        }

    }



}
