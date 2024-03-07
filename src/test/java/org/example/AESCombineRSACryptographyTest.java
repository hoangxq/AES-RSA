package org.example;

import org.example.Object.CipherHybridAesRsaObject;
import org.example.utils.AESCombineRSACryptography;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;

public class AESCombineRSACryptographyTest {
    private final AESCombineRSACryptography aesCombineRSACryptography = new AESCombineRSACryptography();

    public AESCombineRSACryptographyTest() throws NoSuchAlgorithmException {
    }

    @Test
    public void cryptographyTest() throws Exception {
        String plaintext = "Plain Text";
        CipherHybridAesRsaObject cipherObject = aesCombineRSACryptography.encrypt(plaintext);
        String decryptedText = aesCombineRSACryptography.decrypt(cipherObject);
        assertEquals(decryptedText, plaintext);
    }
}
