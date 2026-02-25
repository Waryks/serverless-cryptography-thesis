package com.alexthesis.crypto;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * Generates ephemeral Base64-encoded key material for use in unit tests.
 * Keys are created fresh per test run — no hardcoded secrets in source.
 */
public final class TestKeyFixtures {

    private TestKeyFixtures() {}

    /** Returns a Base64-encoded 256-bit HMAC-SHA256 key. */
    public static String hmacKeyB64() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
            kg.init(256);
            return Base64.getEncoder().encodeToString(kg.generateKey().getEncoded());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Returns a Base64-encoded PKCS#8 DER RSA-2048 private key. */
    public static String rsaKeyB64() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            return Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Returns a Base64-encoded PKCS#8 DER EC P-256 private key. */
    public static String ecKeyB64() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();
            return Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

