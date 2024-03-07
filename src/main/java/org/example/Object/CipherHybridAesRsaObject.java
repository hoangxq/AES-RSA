package org.example.Object;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class CipherHybridAesRsaObject {
    private String cipherText;
    private String keyWrapping;

    @Override
    public String toString() {
        return "\nCipherHybridAesRsaObject{\n" +
                "    cipherText='" + cipherText + '\'' +
                ",\n    keyWrapping='" + keyWrapping + '\'' +
                "\n}";
    }
}