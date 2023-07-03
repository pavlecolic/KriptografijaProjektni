package app.controllers;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import app.utilities.Utilities;

import java.io.IOException;
import java.net.URL;
import java.util.ResourceBundle;

public class LogInController implements Initializable {
    public Label wrongLogin;

    @FXML
    private CheckBox check_login;

    @FXML
    private TextField usernameInput;
    @FXML
    private PasswordField passwordInput;
    @FXML
    private Button logInButton;

    @FXML
    private Label welcomeText;

    @FXML
    private Button backButton;

    private static int strikes = 0;
    @FXML
    private void userLogin(ActionEvent event) throws IOException {

        checkLogin();
    }
    private void checkLogin() throws IOException {
        Main m = new Main();

        if(Utilities.validateLogin(usernameInput.getText(), passwordInput.getText())) {
            strikes = 0;
            m.changeScene("app-main.fxml");
        }
        else {
            strikes++;
            if (strikes == 3) {
                // Revoke certificate ...
                strikes = 0;
                Utilities.revokeCertificate();
                Alert a = new Alert(Alert.AlertType.INFORMATION);
                a.setTitle("Certificate revocation");
                a.setContentText("Your certificate has been revoked. One chance to get credentials right to withdraw...");
                a.setHeaderText("WARNING!");
                a.show();
                // IZMJENA OVDJE
                m.changeScene("final.fxml");
            }

            wrongLogin.setText("Invalid credentials. Strike: " + strikes);
            //obradi u aplikaciji (kazna za 3 pogresna..)
        }
    }

    @FXML
    private void back(ActionEvent event) {
        try {
            Main m = new Main();
            m.changeScene("cert_form.fxml");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {

    }
}