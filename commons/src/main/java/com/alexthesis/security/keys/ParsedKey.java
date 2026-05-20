package com.alexthesis.security.keys;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Separates raw key material from parsed cryptographic key objects.
 *
 * <p>This prevents repeated parsing during warm invocations when caching is enabled.
 * Parsed keys are stored in a cache-friendly format and can be reused across multiple
 * signing/verification operations within the same Lambda execution context.
 */
public record ParsedKey(
        KeyDescriptor descriptor,
        String rawKeyMaterial,
        Key parsedKey
) {

    /**
     * Helper constructor for HMAC keys (where parsedKey is a SecretKey).
     */
    public static ParsedKey hmac(KeyDescriptor descriptor, String base64RawKey, Key secretKey) {
        return new ParsedKey(descriptor, base64RawKey, secretKey);
    }

    /**
     * Helper constructor for asymmetric private keys (used by Producer).
     */
    public static ParsedKey privateKey(KeyDescriptor descriptor, String pemKeyMaterial, PrivateKey key) {
        return new ParsedKey(descriptor, pemKeyMaterial, key);
    }

    /**
     * Helper constructor for asymmetric public keys (used by Consumer).
     */
    public static ParsedKey publicKey(KeyDescriptor descriptor, String pemKeyMaterial, PublicKey key) {
        return new ParsedKey(descriptor, pemKeyMaterial, key);
    }

    /**
     * Returns the cached parsed key if available.
     */
    public Key key() {
        return parsedKey;
    }

    /**
     * Returns the descriptor for audit/logging purposes.
     */
    public KeyDescriptor getDescriptor() {
        return descriptor;
    }
}

