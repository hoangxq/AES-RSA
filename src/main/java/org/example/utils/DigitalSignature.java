package org.example.utils;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.example.Object.DigitalSignatureObject;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

public class DigitalSignature {
    private static final String RSA_ALGORITHM = "RSA";
    private static KeyPair rsaKeyPair = null;

    private static final int RSA_KEY_SIZE = 2048;

    public DigitalSignature() throws NoSuchAlgorithmException {
        rsaKeyPair = generateKeyPairRSA();
    }

    public DigitalSignatureObject createDigitalSignature(String data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(rsaKeyPair.getPrivate());
        signature.update(data.getBytes());
        byte[] signatureBytes = signature.sign();

        return new DigitalSignatureObject(
                Base64.getEncoder().encodeToString(signatureBytes),
                Base64.getEncoder().encodeToString(generateSelfSignedCertificate().getEncoded())
        );
    }

    public X509Certificate generateSelfSignedCertificate() throws Exception {
        Date startDate = new Date();
        Date expiryDate = new Date(startDate.getTime() + 365 * 24 * 60 * 60 * 1000L); // 1 year validity
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        X509Certificate cert;
        X500Principal subjectName = new X500Principal("CN=Self Signed Certificate");

        KeyPair keyPair = new KeyPair(rsaKeyPair.getPublic(), rsaKeyPair.getPrivate());

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X509Principal dnName = new X509Principal(subjectName.toString());

        certGen.setSerialNumber(serialNumber);
        certGen.setSubjectDN(dnName);
        certGen.setIssuerDN(dnName);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256withRSA");

        cert = certGen.generate(keyPair.getPrivate());
        return cert;
    }

    private static KeyPair generateKeyPairRSA() throws NoSuchAlgorithmException {
        // create keyPair by RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(RSA_KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }
}
