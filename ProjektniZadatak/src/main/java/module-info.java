module app.projektnizadatak {
    requires javafx.controls;
    requires javafx.fxml;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;


    opens app.controllers to javafx.fxml;
    exports  app.controllers;
}