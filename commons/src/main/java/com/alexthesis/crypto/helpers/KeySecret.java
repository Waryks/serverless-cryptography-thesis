package com.alexthesis.crypto.helpers;

/**
 * Represents the JSON structure stored in AWS Secrets Manager for a key entry.
 * The {@code keyMaterial} field holds the Base64-encoded raw key bytes (HMAC) or
 * a PEM-encoded private key (RSA / ECDSA).
 */
public record KeySecret(
        String keyId,
        String algorithm,
        String keyMaterial
) {}

