package com.alexthesis.security.keys;

import com.alexthesis.crypto.helpers.KeySecret;

import java.security.Key;
import java.util.Optional;

/**
 * Resolves cryptographic keys from the Key Management Subsystem.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Resolve current key by algorithm</li>
 *   <li>Resolve previous key by algorithm (if rotation is allowed)</li>
 *   <li>Select keys based on algorithm compatibility</li>
 *   <li>Support policy-driven rotation behavior</li>
 *   <li>Coordinate with KeyProvider, KeyParser, and KeyCache</li>
 * </ul>
 *
 * <p>Usage example:
 * <pre>
 *   ParsedKey currentKey = resolver.resolveCurrent(Algorithm.RSA_PSS_SHA256, false);
 *   // or for fallback:
 *   ParsedKey previousKey = resolver.resolvePrevious(Algorithm.RSA_PSS_SHA256, false);
 * </pre>
 */
public class KeyResolver {

    private final KeyProvider keyProvider;
    private final KeyCache keyCache;
    private final RotationPolicy rotationPolicy;

    /**
     * Creates a KeyResolver with the given components.
     *
     * @param keyProvider the provider for retrieving secrets from Secrets Manager
     * @param keyCache the cache for storing parsed keys (optional)
     * @param rotationPolicy the rotation policy to apply during resolution
     */
    public KeyResolver(KeyProvider keyProvider, KeyCache keyCache, RotationPolicy rotationPolicy) {
        this.keyProvider = keyProvider;
        this.keyCache = keyCache;
        this.rotationPolicy = rotationPolicy;
    }

    /**
     * Resolves the current signing/verification key for the given algorithm.
     *
     * <p>Follows this resolution order:
     * <ol>
     *   <li>Check cache for current key</li>
     *   <li>Fetch from Secrets Manager using "thesis/{algorithm}/current"</li>
     *   <li>Parse and cache the key</li>
     *   <li>Return the parsed key</li>
     * </ol>
     *
     * @param algorithm the algorithm string (e.g., "HMAC_SHA256", "RSA_PSS_SHA256")
     * @param isPublicKey true for public key (Consumer), false for private key (Producer)
     * @return the resolved and parsed current key
     * @throws RuntimeException if resolution fails
     */
    public ParsedKey resolveCurrent(String algorithm, boolean isPublicKey) {
        String algorithmLower = algorithm.replaceAll("_", "").toLowerCase();
        String secretId = KeyProvider.buildSecretId(algorithmLower, "current");

        return resolveKey(secretId, KeyDescriptor.KeyStage.CURRENT, algorithm, isPublicKey);
    }

    /**
     * Resolves the previous key for the given algorithm, if rotation is allowed.
     *
     * <p>Follows this resolution order:
     * <ol>
     *   <li>Check if rotation policy allows previous-key verification</li>
     *   <li>Check cache for previous key</li>
     *   <li>Fetch from Secrets Manager using "thesis/{algorithm}/previous"</li>
     *   <li>Parse and cache the key</li>
     *   <li>Return the parsed key</li>
     * </ol>
     *
     * @param algorithm the algorithm string
     * @param isPublicKey true for public key, false for private key
     * @return an Optional containing the previous key if available and rotation allows it
     * @throws RuntimeException if rotation is allowed but resolution fails
     */
    public Optional<ParsedKey> resolvePrevious(String algorithm, boolean isPublicKey) {
        if (!rotationPolicy.allowsPreviousKey()) {
            return Optional.empty();
        }

        try {
            String algorithmLower = algorithm.replaceAll("_", "").toLowerCase();
            String secretId = KeyProvider.buildSecretId(algorithmLower, "previous");
            ParsedKey previousKey = resolveKey(secretId, KeyDescriptor.KeyStage.PREVIOUS, algorithm, isPublicKey);
            return Optional.of(previousKey);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /**
     * Internal method to resolve a key by secret ID.
     *
     * @param secretId the Secrets Manager secret ID
     * @param stage the key stage (CURRENT or PREVIOUS)
     * @param algorithm the algorithm string
     * @param isPublicKey true for public key, false for private key
     * @return the resolved and parsed key
     */
    private ParsedKey resolveKey(String secretId, KeyDescriptor.KeyStage stage, String algorithm, boolean isPublicKey) {
        // Check cache first
        Optional<ParsedKey> cached = keyCache.get(secretId);
        if (cached.isPresent()) {
            return cached.get();
        }

        // Fetch from Secrets Manager
        KeySecret secret = keyProvider.retrieveSecret(secretId);

        // Validate algorithm compatibility
        KeyValidationResult validation = KeyValidationResult.validate(secret.algorithm(), secret.keyMaterial());
        if (!validation.isValid()) {
            throw new RuntimeException("Key validation failed: " + validation.getErrorMessage());
        }

        // Parse the key
        Key parsedKeyObject = KeyParser.parse(secret.algorithm(), secret.keyMaterial(), isPublicKey);

        // Create descriptor
        KeyDescriptor descriptor = new KeyDescriptor(
                secret.keyId(),
                secret.algorithm(),
                stage,
                System.currentTimeMillis(),
                secretId
        );

        // Create parsed key
        ParsedKey parsedKey = new ParsedKey(descriptor, secret.keyMaterial(), parsedKeyObject);

        // Cache it
        keyCache.put(secretId, parsedKey);

        return parsedKey;
    }

    /**
     * Resolves a current private key for signing (Producer).
     *
     * @param algorithm the algorithm string
     * @return the resolved private key
     */
    public ParsedKey resolveCurrentPrivateKey(String algorithm) {
        return resolveCurrent(algorithm, false);
    }

    /**
     * Resolves a current public key for verification (Consumer).
     *
     * @param algorithm the algorithm string
     * @return the resolved public key
     */
    public ParsedKey resolveCurrentPublicKey(String algorithm) {
        return resolveCurrent(algorithm, true);
    }

    /**
     * Resolves a previous public key for rotation-aware verification (Consumer).
     *
     * @param algorithm the algorithm string
     * @return an Optional containing the previous public key if available
     */
    public Optional<ParsedKey> resolvePreviousPublicKey(String algorithm) {
        return resolvePrevious(algorithm, true);
    }

    /**
     * Returns the rotation policy in use.
     */
    public RotationPolicy getRotationPolicy() {
        return rotationPolicy;
    }

    /**
     * Returns the cache (for cache control and monitoring).
     */
    public KeyCache getCache() {
        return keyCache;
    }
}




