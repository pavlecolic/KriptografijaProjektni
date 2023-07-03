package app.controllers;

import app.utilities.Utilities;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.ResourceBundle;

public class SignUpController implements Initializable {
    @FXML
    private TextField usernameField;
    @FXML
    private PasswordField passwordField;
    @FXML
    private Button loginButton;
    @FXML
    private Button signUpButton;
    @FXML
    private Label signUpText;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {

    }

    @FXML
    private void backToLogin(ActionEvent event) {
        Main m = new Main();
        try {
            m.changeScene("cert_form.fxml");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @FXML
    private void signUpClicked(ActionEvent event) {

        if (Utilities.validateSignup(usernameField.getText(), passwordField.getText())) {
            signUpText.setText("Uspjesno kreiran sertifikat.");

        } else {
            signUpText.setText("Neuspjesno kreiranje sertifikata");

        }
    }

}
