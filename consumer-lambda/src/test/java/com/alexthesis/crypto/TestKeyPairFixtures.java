package com.alexthesis.crypto;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * Generates ephemeral key material for use in tests.
 * Produces both private (for signing) and public (for verification) key material
 * so the full producer → consumer pipeline can be exercised without real AWS keys.
 */
public final class TestKeyPairFixtures {

    private TestKeyPairFixtures() {}

    /** Returns a Base64-encoded 256-bit HMAC-SHA256 symmetric key. */
    public static String hmacKeyB64() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
            kg.init(256);
            return Base64.getEncoder().encodeToString(kg.generateKey().getEncoded());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Returns an RSA-2048 key pair with Base64-encoded PKCS#8 private and X.509 public keys. */
    public static KeyMaterial rsaKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            return new KeyMaterial(
                    Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()),
                    Base64.getEncoder().encodeToString(kp.getPublic().getEncoded())
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Returns an EC P-256 key pair with Base64-encoded PKCS#8 private and X.509 public keys. */
    public static KeyMaterial ecKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();
            return new KeyMaterial(
                    Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()),
                    Base64.getEncoder().encodeToString(kp.getPublic().getEncoded())
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Holds a matched private + public key pair encoded as Base64.
     *
     * @param privateKeyB64 PKCS#8 DER private key — used by the producer to sign
     * @param publicKeyB64  X.509 DER public key — stored in Secrets Manager, used by the consumer to verify
     */
    public record KeyMaterial(String privateKeyB64, String publicKeyB64) {}
}

