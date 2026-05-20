package com.alexthesis.security.keys;

import com.alexthesis.crypto.helpers.CryptoUtils;
import com.alexthesis.messaging.Algorithm;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Parses raw key material into cryptographic Key objects.
 *
 * <p>Supports conversion of:
 * <ul>
 *   <li>HMAC keys: Base64-decoded bytes → SecretKey for HmacSHA256</li>
 *   <li>RSA keys: PEM-encoded → PrivateKey or PublicKey</li>
 *   <li>ECDSA keys: PEM-encoded → PrivateKey or PublicKey</li>
 * </ul>
 *
 * <p>This parser is used during key resolution and is called before caching
 * to allow warm invocations to reuse the parsed Key object.
 */
public class KeyParser {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String EC_ALGORITHM = "EC";

    /**
     * Parses raw key material into a cryptographic Key object.
     *
     * @param algorithm the algorithm string (e.g., "HMAC_SHA256", "RSA_PSS_SHA256")
     * @param keyMaterial the raw key material (Base64 for HMAC, PEM for asymmetric)
     * @param isPublicKey true if parsing a public key, false for private key
     * @return the parsed Key object
     * @throws RuntimeException if parsing fails
     */
    public static Key parse(String algorithm, String keyMaterial, boolean isPublicKey) {
        // Validate first
        KeyValidationResult validation = KeyValidationResult.validate(algorithm, keyMaterial);
        if (!validation.isValid()) {
            throw new RuntimeException("Key validation failed: " + validation.getErrorMessage());
        }

        if (algorithm.contains("HMAC")) {
            return parseHmacKey(keyMaterial);
        } else if (algorithm.contains("RSA")) {
            return parseRsaKey(keyMaterial, isPublicKey);
        } else if (algorithm.contains("ECDSA")) {
            return parseEcdsaKey(keyMaterial, isPublicKey);
        } else {
            throw new RuntimeException("Unsupported algorithm: " + algorithm);
        }
    }

    /**
     * Parses a Base64-encoded HMAC key.
     *
     * @param base64Key the Base64-encoded key material
     * @return a SecretKey suitable for HmacSHA256
     */
    private static Key parseHmacKey(String base64Key) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            return new SecretKeySpec(keyBytes, 0, keyBytes.length, "HmacSHA256");
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse HMAC key", e);
        }
    }

    /**
     * Parses an RSA key (public or private based on {@code isPublicKey}).
     *
     * @param pemKey the PEM-encoded RSA key
     * @param isPublicKey true for public key, false for private key
     * @return the parsed RSA key
     */
    private static Key parseRsaKey(String pemKey, boolean isPublicKey) {
        try {
            byte[] derBytes = Base64.getDecoder().decode(CryptoUtils.stripPemHeaders(pemKey));

            if (isPublicKey) {
                return KeyFactory.getInstance(RSA_ALGORITHM)
                        .generatePublic(new X509EncodedKeySpec(derBytes));
            } else {
                return KeyFactory.getInstance(RSA_ALGORITHM)
                        .generatePrivate(new PKCS8EncodedKeySpec(derBytes));
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse RSA key", e);
        }
    }

    /**
     * Parses an ECDSA P-256 key (public or private based on {@code isPublicKey}).
     *
     * @param pemKey the PEM-encoded ECDSA key
     * @param isPublicKey true for public key, false for private key
     * @return the parsed ECDSA key
     */
    private static Key parseEcdsaKey(String pemKey, boolean isPublicKey) {
        try {
            byte[] derBytes = Base64.getDecoder().decode(CryptoUtils.stripPemHeaders(pemKey));

            if (isPublicKey) {
                return KeyFactory.getInstance(EC_ALGORITHM)
                        .generatePublic(new X509EncodedKeySpec(derBytes));
            } else {
                return KeyFactory.getInstance(EC_ALGORITHM)
                        .generatePrivate(new PKCS8EncodedKeySpec(derBytes));
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse ECDSA key", e);
        }
    }

    /**
     * Convenience method for parsing private keys (used by Producer).
     */
    public static PrivateKey parsePrivateKey(String algorithm, String keyMaterial) {
        return (PrivateKey) parse(algorithm, keyMaterial, false);
    }

    /**
     * Convenience method for parsing public keys (used by Consumer).
     */
    public static PublicKey parsePublicKey(String algorithm, String keyMaterial) {
        return (PublicKey) parse(algorithm, keyMaterial, true);
    }
}

