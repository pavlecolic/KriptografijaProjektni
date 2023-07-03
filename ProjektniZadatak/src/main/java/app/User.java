package app;

import org.bouncycastle.asn1.x509.Certificate;

import java.nio.charset.StandardCharsets;

public class User {
    private String username;
    private Certificate certificate;
    private byte[] hashedPassword;
    private byte[] salt;
}
