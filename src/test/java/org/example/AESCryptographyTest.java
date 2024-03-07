package org.example;

import org.example.utils.AESCryptography;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class AESCryptographyTest {
    private final AESCryptography aesCryptography = new AESCryptography();

    @Test
    public void cryptographyTest() throws Exception {
        String plaintext = "Plain Text";
        String ciphertext = aesCryptography.encrypt(plaintext);
        String decryptedText = aesCryptography.decrypt(ciphertext);
        assertEquals(decryptedText, plaintext);
    }
}