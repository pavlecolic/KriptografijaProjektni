package app.utilities;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;
import java.util.Set;

public class Cryptography {

    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";


    // Kreiranje korisnickog sertifikata
    public static X509Certificate makeV3Certificate(PrivateKey caPrivateKey, PublicKey eePublicKey, String certName)
            throws GeneralSecurityException, CertIOException, OperatorCreationException
    {
        // Load the CA certificate
        X509Certificate caCertificate = Utilities.getCertificateFromFile(new File(Utilities.CA_CERT));
        // load CA private key

        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
                caCertificate.getSubjectX500Principal(),
                BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(10)),
                new Date(System.currentTimeMillis() - 1000L * 5),
                new Date(System.currentTimeMillis() + ExValues.SIX_MONTHS),
                new X500Principal("CN="+certName), eePublicKey);

        //
        // extensions
        //
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        v3CertBldr.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(eePublicKey));

        v3CertBldr.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(caCertificate.getPublicKey()));

        v3CertBldr.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(false));

        v3CertBldr.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.encipherOnly)
        );

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(v3CertBldr.build(signerBuilder.build(caPrivateKey)));
    }

    // Funkcija za generisanje para RSA kljuceva
    public static KeyPair generateKeyPair()
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            KeyPairGenerator keyPair = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);

            keyPair.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
            return keyPair.generateKeyPair();

        } catch (GeneralSecurityException e) {
            System.out.println("PROBLEM GENERATING KEY PAIR");
            return null;
        }
    }

    // CRL lista i povlacenje sertifikata
    public static X509CRL makeV2Crl()
            throws GeneralSecurityException, CertIOException, OperatorCreationException
    {
        X509Certificate caCert = Utilities.getCertificateFromFile(new File(Utilities.CA_CERT));
        PrivateKey caPrivateKey = Utilities.readKey("CAkey");
        Date now = new Date();
        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(), now);

        crlGen.setNextUpdate(new Date(System.currentTimeMillis() + ExValues.THIRTY_DAYS));

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(caCert.getPublicKey()));

        X509CRLHolder crl = crlGen.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(caPrivateKey));

        return new JcaX509CRLConverter().setProvider(BC_PROVIDER).getCRL(crl);
    }


    public static X509CRL addRevocationToCRL(
            PrivateKey caKey,
            X509CRL crl,
            X509Certificate certToRevoke)
            throws IOException, GeneralSecurityException, OperatorCreationException
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(crl);

        crlGen.setNextUpdate(new Date(ExValues.WEEK));

        // add revocation
        ExtensionsGenerator extGen = new ExtensionsGenerator();

        CRLReason crlReason = CRLReason.lookup(CRLReason.certificateHold);


        extGen.addExtension(Extension.reasonCode, false, crlReason);
        crlGen.addCRLEntry(certToRevoke.getSerialNumber(),
                new Date(), extGen.generate());

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(caKey);
        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider(BC_PROVIDER);
        return converter.getCRL(crlGen.build(signer));
    }

    // Funkcija za digest lozinke
    public static String digest(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(password.getBytes(StandardCharsets.UTF_8));
            byte[] digest = md.digest();
            return String.format("%064x", new BigInteger(1, digest));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("PROBLEM SA HESIRANJEM LOZINKE");
        }
        return "";
    }

    // Funkcija za digest lozinke
    public static String digestFile(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytes);
            byte[] digest = md.digest();
            return String.format("%064x", new BigInteger(1, digest));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("PROBLEM SA HESIRANJEM FAJLA");
        }
        return "";
    }

    public static boolean checkCertificateValidity(X509Certificate certificate) {
        try {
            certificate.checkValidity();

            FileInputStream finCA = new FileInputStream(Utilities.CA_CERT);
            CertificateFactory fCA = CertificateFactory.getInstance("X.509");
            X509Certificate certificateCA = (X509Certificate) fCA.generateCertificate(finCA);
            PublicKey publicKeyCA = certificateCA.getPublicKey();

            certificate.verify(publicKeyCA);

            File crlListFile = new File(Utilities.CRL);
            byte[] crlBytes = Files.readAllBytes(Paths.get(crlListFile.getPath()));

            InputStream inStream = new ByteArrayInputStream(crlBytes);
            CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
            X509CRL crlList = (X509CRL) cf2.generateCRL(inStream);

            //X509CRL crlList;
            if (crlList.isRevoked(certificate)) {
                throw new CertificateException("Certificate revoked");
            }
            System.out.println("Sve je dobro....");
        } catch (Exception ex) {
            System.out.println("Exceptin INVALID CERTIFICARTE: " + ex.toString());
            return false;
        }
        return true;
    }

    public static void removeFromCRL() {
        X509Certificate certificate = Utilities.getCertificateFromFile(new File(Utilities.USER_CERTS + File.separator + Utilities.CURRENT_USER_USERNAME + ".crt"));

        X509CRL crl = Utilities.readCRLFromFile();
        Set<? extends  X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();
        X509CRLEntry entryToRemove = null;
        for (X509CRLEntry entry : revokedCertificates) {
            if (entry.getSerialNumber().equals(certificate.getSerialNumber())) {
                entryToRemove = entry;
                break;
            }
        }
        revokedCertificates.remove(entryToRemove);
        try {
            crl = Cryptography.makeV2Crl();
            Utilities.writeCRLToFIle(crl);
        }catch (Exception e) {
            e.printStackTrace();
        }

    }

}
