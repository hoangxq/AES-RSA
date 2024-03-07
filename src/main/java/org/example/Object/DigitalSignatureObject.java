package org.example.Object;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class DigitalSignatureObject {
    private String digitalSignature;
    private String selfSignedCertificate;

    @Override
    public String toString() {
        return "\nDigitalSignatureObject{\n" +
                "   digitalSignature='" + digitalSignature + '\'' +
                ",\n   selfSignedCertificate='" + selfSignedCertificate + '\'' +
                "\n}";
    }
}
