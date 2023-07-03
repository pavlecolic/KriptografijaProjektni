package app.controllers;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import app.utilities.Utilities;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ResourceBundle;


public class CertFormController implements Initializable {


    FileChooser fileChooser = new FileChooser();
    @FXML
    private TextArea certificateText;
    @FXML
    private Button certificateButton;
    @FXML
    private Button signUpButton;
    @FXML
    private Label labelInvalidCert;
    @FXML
    void getCertificateFile(ActionEvent event) {
        File certificate = fileChooser.showOpenDialog(new Stage());
        labelInvalidCert.setText("Select a certificate");
        // validacija sertifikata
        if(certificate != null) {
            String username = Utilities.checkCertValidity(certificate);
            if (!"".equals(username)) {
                Main m = new Main();
                try {
                    m.changeScene("log-in.fxml");
                } catch (IOException e) {
                    e.printStackTrace();
                }

            } else {
                // Obavijesti korisnika o nevalidnosti
                labelInvalidCert.setText("Invalid certificate");
            }
        }
    }
    @FXML
    void  signUpButtonClick(ActionEvent event) {
        Main m = new Main();
        try {
            m.changeScene("sign-up.fxml");
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        File file = new File("input");
        fileChooser.setInitialDirectory(file);
    }
}
