package com.alexthesis.security.keys;

/**
 * Metadata describing a cryptographic key without exposing key material.
 *
 * <p>Used for audit logging, rotation tracking, and benchmark instrumentation.
 */
public record KeyDescriptor(
        String keyId,
        String algorithm,
        KeyStage stage,
        long loadedAtEpochMs,
        String source
) {

    /**
     * The lifecycle stage of a key.
     */
    public enum KeyStage {
        CURRENT,
        PREVIOUS
    }

    /**
     * Constructs a KeyDescriptor with current timestamp.
     */
    public static KeyDescriptor current(String keyId, String algorithm, String source) {
        return new KeyDescriptor(
                keyId,
                algorithm,
                KeyStage.CURRENT,
                System.currentTimeMillis(),
                source
        );
    }

    /**
     * Constructs a KeyDescriptor for a previous-stage key.
     */
    public static KeyDescriptor previous(String keyId, String algorithm, String source) {
        return new KeyDescriptor(
                keyId,
                algorithm,
                KeyStage.PREVIOUS,
                System.currentTimeMillis(),
                source
        );
    }
}

