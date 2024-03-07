package org.example;

import org.example.Object.CipherHybridAesRsaObject;
import org.example.Object.DigitalSignatureObject;
import org.example.utils.AESCombineRSACryptography;
import org.example.utils.AESCryptography;
import org.example.utils.DigitalSignature;

/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) throws Exception {
        AESCryptography aesCryptography = new AESCryptography();
        AESCombineRSACryptography aesCombineRSACryptography = new AESCombineRSACryptography();

        // encrypt
        String plaintext = "Plain Text";
        String ciphertextByAES = aesCryptography.encrypt(plaintext);
        CipherHybridAesRsaObject cipherHybridAesRsaObject = aesCombineRSACryptography.encrypt(plaintext);
        System.out.println("Ciphertext by AES: " + ciphertextByAES);
        System.out.println("Ciphertext by AES combine RSA: " + cipherHybridAesRsaObject);

        // decrypt
        String decryptedTextByAES = aesCryptography.decrypt(ciphertextByAES);
        String decryptedTextByAESCombineRSA = aesCombineRSACryptography.decrypt(cipherHybridAesRsaObject);
        System.out.println("Decrypted text by AES: " + decryptedTextByAES);
        System.out.println("Decrypted text by AES combine RSA: " + decryptedTextByAESCombineRSA);

        // digital signature
        DigitalSignature digitalSignature = new DigitalSignature();
        DigitalSignatureObject digitalSignatureObject = digitalSignature.createDigitalSignature(plaintext);
        System.out.println(digitalSignatureObject);
    }
}
