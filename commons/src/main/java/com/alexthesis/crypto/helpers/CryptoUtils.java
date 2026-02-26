package com.alexthesis.crypto.helpers;

import com.alexthesis.messaging.SignedContent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/**
 * Shared cryptographic utilities used by both the producer (signing) and consumer (verification).
 *
 * <h2>Canonical serialisation</h2>
 * {@link #canonicalise(SignedContent, ObjectMapper)} produces a deterministic UTF-8 byte
 * representation of a {@link SignedContent} record by sorting map entries alphabetically.
 * Both sides of the pipeline <b>must</b> use this method to guarantee byte-level equivalence.
 *
 * <h2>PEM handling</h2>
 * {@link #stripPemHeaders(String)} removes PEM header/footer lines and whitespace so
 * the remaining string is pure Base64-encoded DER.
 */
public final class CryptoUtils {

    private CryptoUtils() {}

    /**
     * Creates an {@link ObjectMapper} copy configured for canonical (deterministic) serialisation.
     * {@link SerializationFeature#ORDER_MAP_ENTRIES_BY_KEYS} sorts all map entries alphabetically
     * before converting to bytes, ensuring the same logical content always produces the same byte
     * sequence regardless of insertion order.
     *
     * @param source the base ObjectMapper to copy settings from
     * @return a new ObjectMapper configured for canonical serialisation
     */
    public static ObjectMapper canonicalMapper(ObjectMapper source) {
        return source.copy()
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    }

    /**
     * Produces a deterministic UTF-8 byte representation of a {@link SignedContent}.
     * Fields are ordered so that the byte sequence is stable across JVM invocations
     * and Jackson versions.
     *
     * @param content the event content to serialise
     * @param canonicalMapper an ObjectMapper obtained from {@link #canonicalMapper(ObjectMapper)}
     * @return canonical byte representation
     * @throws RuntimeException if serialisation fails
     */
    public static byte[] canonicalise(SignedContent content, ObjectMapper canonicalMapper) {
        try {
            return canonicalMapper.writeValueAsBytes(content);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialise SignedContent canonically", e);
        }
    }

    /**
     * Strips PEM header/footer lines and whitespace so the remaining string
     * is pure Base64-encoded DER — works for both raw-Base64 and PEM inputs.
     *
     * @param pem a PEM-encoded string or raw Base64
     * @return the Base64-encoded DER without headers, footers, or whitespace
     */
    public static String stripPemHeaders(String pem) {
        return pem.replaceAll("-----[^-]+-----", "")
                  .replaceAll("\\s", "");
    }
}

