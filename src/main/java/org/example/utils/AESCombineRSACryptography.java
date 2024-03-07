package org.example.utils;

import org.example.Object.CipherHybridAesRsaObject;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESCombineRSACryptography {
    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_MODE = "AES/CBC/PKCS5Padding";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
    private static final String SECRET_KEY = "secret-key-12345";
    private static final IvParameterSpec IV = generateIv();
    private static KeyPair rsaKeyPair = null;

    private static final int RSA_KEY_SIZE = 2048;

    public AESCombineRSACryptography() throws NoSuchAlgorithmException {
        rsaKeyPair = generateKeyPairRSA();
    }

    public CipherHybridAesRsaObject encrypt(String plaintext) throws Exception {
        // encrypt plaintext
        SecretKeySpec secretKeySpec = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), AES_ALGORITHM);
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, IV);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());

        // key wrapping - encrypt SECRET_KEY use public key make by RSA
        Cipher rsaCipher = Cipher.getInstance(RSA_MODE);
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
        byte[] aesKeyBytes = rsaCipher.doFinal(SECRET_KEY.getBytes());

        return new CipherHybridAesRsaObject(
                Base64.getEncoder().encodeToString(encrypted),
                Base64.getEncoder().encodeToString(aesKeyBytes)
        );
    }

    public String decrypt(CipherHybridAesRsaObject cipherObject) throws Exception {
        // key wrapping - decrypt SECRET_KEY use private key make by RSA
        Cipher rsaCipher = Cipher.getInstance(RSA_MODE);
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
        byte[] aesKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(cipherObject.getKeyWrapping()));
        String aesSecretKey = new String(aesKeyBytes, StandardCharsets.UTF_8);
        if (!aesSecretKey.equals(SECRET_KEY))
            return "SECRET_KEY is not match";

        SecretKeySpec secretKeySpec = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), AES_ALGORITHM);
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, IV);
        byte[] decoded = Base64.getDecoder().decode(cipherObject.getCipherText());
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }


    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static KeyPair generateKeyPairRSA() throws NoSuchAlgorithmException {
        // create keyPair by RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(RSA_KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }
}