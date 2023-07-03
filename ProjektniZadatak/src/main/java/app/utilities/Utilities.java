package app.utilities;

import app.User;
import javafx.scene.chart.ScatterChart;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.jce.provider.BrokenPBE;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class Utilities {
    // ova klasa ce da sadrzi metode za citanje i pisanje iz fajlova, jos neka logika
    public static final String separator = File.separator;
    public static final String  CA_CERT = "src" + separator + "main" + separator + "java" +separator + "pki" + separator  + "CAcert.crt";
    public static final String USER_CERTS = "src" + separator + "main" + separator + "java" +separator + "pki" + separator + "certificates";
    public static final String CRL = "src" + separator + "main" + separator + "java" +separator + "pki" + separator +  "crl" + separator + "crl_list.crl";
    public static final String KEYSTORE = "src" + separator + "main" + separator + "java" +separator + "pki" + separator  +"keystore";
    public static final String USERS = "src" + separator + "main" + separator + "java" +separator + "pki" + separator  + "users" + separator + "users";
    public static final String REPOSITORY = "src" + separator + "main" + separator + "java" +separator  + "repository";
    // Default input/output file for users
    public static final String USER_IO = "input";
    public static String CURRENT_USER_USERNAME;
    // trenutni korisnik se odredjuje na osnovu sertifikata
    public User current_user;


    public static String checkCertValidity(File file) {

        CURRENT_USER_USERNAME = "";
        String returnUsername = "";

        Path file1 = Paths.get(file.getPath());
        File dir = new File(USER_CERTS);
        X509Certificate providedCert = Utilities.getCertificateFromFile(file);

        // DODATI DA IMA JEDAN POKUSAJ DA VRATI SERTIFIKAT
        if(!Cryptography.checkCertificateValidity(providedCert)) {
            return "";
        }
        String[] ls = dir.list();
        System.out.println(file1.toAbsolutePath());

        for (int i = 0; i < ls.length; i++) {

            Path file2 = Paths.get(USER_CERTS + separator + ls[i]);
            //System.out.println(file2.toAbsolutePath());
            try {
                String content1 = new String(Files.readAllBytes(file1));
                String content2 = new String(Files.readAllBytes(file2));
                if (content1.equals(content2)) {
                    String[] split = file2.getFileName().toString().split("\\.");
                    CURRENT_USER_USERNAME = split[0];
                    returnUsername = CURRENT_USER_USERNAME;
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    // Utilities.initiateCurrentUser();
                    return returnUsername;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } return returnUsername;
    }


    public static boolean validateLogin(String username, String password) {
        // provjeri da li podaci odgovaraju...
        if (CURRENT_USER_USERNAME.equals(username)) {
            // izvuci lozinku i podatke iz users fajla
            try {
                List<String> lines = Files.readAllLines(Paths.get(USERS));
                for (String line : lines) {
                    String[] split = line.split(";");
                    if(username.equals(split[0])){
                        // obezbijediti hesiranje !!!
                        if(Cryptography.digest(password).equals(split[1])) {
                            return true;
                        }
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

            return false;
        } else {
            return false;
        }
    }

    public static boolean validateSignup(String username, String password) {
        // check the validity of a given username
        try {
            List<String> lines = Files.readAllLines(Paths.get(USERS));
            for (String line : lines) {
                String[] split = line.split(";");
                if(username.equals(split[0])){
                    System.out.println("USERNAME EXISTS");
                    return false;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // if the username is valid issue the certificate and put it in the certificates folder
        KeyPair userKeyPair = Cryptography.generateKeyPair();
        // Kreiranje novog sertifikata i upis u odgovarajuce fajlove
        try {
            // Upis korisnickog kljcua u fajl
            if (userKeyPair != null) {
                Utilities.saveKeyPair(userKeyPair, username);
                // Citanje privatnog kljuca i kreiranjesertifikata
                PrivateKey caPrivateKey = Utilities.readKey("CAkey");
                X509Certificate newCert = Cryptography.makeV3Certificate(caPrivateKey, userKeyPair.getPublic(), username);
                System.out.println(newCert);
                Utilities.writeCertificateToFile(newCert, username);
                Utilities.returnCertificateToUser(newCert, username);
            }
        } catch (IOException | OperatorCreationException | GeneralSecurityException  e) {
            System.out.println("Problem Generating");
        }
        // form username.crt
        // Add the new info about the user to users.txt file (username;salt;hash(password, salt))
        String newInfo = username + ";"  + Cryptography.digest(password); // HASHING
        try (FileWriter writer = new FileWriter(USERS, true)) {
            writer.write(newInfo + System.lineSeparator());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return true;
    }

    public static String getCurrentUser() {
        return CURRENT_USER_USERNAME;
    }

    // Upis X509 scert-a u fajl
    public static void writeCertificateToFile(X509Certificate certificate, String username) throws IOException, CertificateEncodingException {
        File certLocation = new File(USER_CERTS + separator + username + ".crt");
        if(certLocation.createNewFile()) {
            PemWriter pemWriter = new PemWriter(new FileWriter(certLocation));

            pemWriter.writeObject(new PemObject("X509_CERTIFICATE", certificate.getEncoded()));
            pemWriter.flush();
            pemWriter.close();
        }
    }

    public static void returnCertificateToUser(X509Certificate certificate, String username) throws IOException, CertificateEncodingException {
        File userDir = new File(USER_IO + File.separator + username);
        if(!userDir.exists()) {
            userDir.mkdir();
        }
        File certLocation = new File(userDir.getCanonicalPath() + File.separator + username + ".crt");
        if(certLocation.createNewFile()) {
            PemWriter pemWriter = new PemWriter(new FileWriter(certLocation));

            pemWriter.writeObject(new PemObject("X509_CERTIFICATE", certificate.getEncoded()));
            pemWriter.flush();
            pemWriter.close();
        }
    }

    public static X509CRL readCRLFromFile() {
        try {
            FileInputStream fis = new FileInputStream(CRL);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(fis);
            System.out.println("Issuer: " + crl.getIssuerX500Principal());
            if(crl.getRevokedCertificates() != null) {
                System.out.println("Number of revoked certificates: " + crl.getRevokedCertificates().size());
            }
            fis.close();
            return crl;
        }catch (CRLException e) {
            System.out.println("PROBLEM READIONG CRL - CRLException");
            return null;
        }
        catch (CertificateException e) {
            System.out.println("PROBLEM READING CRL - Certificate exc");
            return null;

        }
        catch (FileNotFoundException e) {
            System.out.println("PROBLEM READING CRL - File Not Found");
            return null;

        }
        catch (IOException e) {
            System.out.println("PROBLEM READING CRL - IOException");
            return null;

        }
    }

    public static void writeCRLToFIle(X509CRL crl) throws IOException, CRLException {
        PemWriter pemWriter = new PemWriter(new FileWriter(CRL));
        File crlLocation = new File(CRL);
        pemWriter.writeObject(new PemObject("X509CRL", crl.getEncoded()));
        pemWriter.flush();
        pemWriter.close();
    }

    // Write key to file
    public static void writeKey(KeyPair keyPair, String username) throws  IOException{
        PemWriter pemWriter = new PemWriter(new FileWriter(KEYSTORE + File.separator + username + ".key"));
        pemWriter.writeObject(new PemObject("PRIVATE_KEY", keyPair.getPrivate().getEncoded()));
        pemWriter.flush();
        pemWriter.close();
    }

    public static RSAPrivateKey readKey(String username) throws InvalidKeySpecException, NoSuchAlgorithmException {
        try (FileReader keyReader = new FileReader(KEYSTORE + separator + username + ".key")) {

            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());

            return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
        } catch (IOException e) {
            System.out.println("PROBLEM READING KEY");
        }
        return null;
    }

    // Dohvatanje sertifikata iz fajla
    public static X509Certificate getCertificateFromFile(File file) {
        try {
            FileInputStream fin = new FileInputStream(file.getPath());
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            return (X509Certificate) f.generateCertificate(fin);

        } catch (Exception ex) {
            System.out.println("EXCEPTION invalid certificate: " + ex.toString());
            return null;
        }
    }

    public static void revokeCertificate() {
        try {
            System.out.println("Revoking cert from user: " + CURRENT_USER_USERNAME);
            X509Certificate certificate = Utilities.getCertificateFromFile(new File(USER_CERTS + File.separator + CURRENT_USER_USERNAME + ".crt"));
            System.out.println(certificate);
            X509CRL crl = Utilities.readCRLFromFile();
            PrivateKey caKey =  Utilities.readKey("CAkey");
            System.out.println(caKey);
            if(certificate != null) {
                X509CRL newCRL = Cryptography.addRevocationToCRL(caKey, crl, certificate);
                Utilities.writeCRLToFIle(newCRL);
            }

        }
        catch (IOException | OperatorCreationException | GeneralSecurityException e) {
           e.printStackTrace();
        }
    }
    public static void saveKeyPair(KeyPair keyPair, String username)  {
        try {
            FileOutputStream fileOut = new FileOutputStream(KEYSTORE + File.separator + username + ".key");
            ObjectOutputStream out = new ObjectOutputStream(fileOut);
            out.writeObject(keyPair);
            out.close();
            fileOut.close();
        }catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static KeyPair readKeyPair(String username) throws IOException, ClassNotFoundException{

            FileInputStream fileIn = new FileInputStream(KEYSTORE + File.separator + username + ".key");
            ObjectInputStream in = new ObjectInputStream(fileIn);
            KeyPair keyPair = (KeyPair) in.readObject();
            in.close();
            fileIn.close();
            return keyPair;
    }


}
