package com.alexthesis.security.keys;

import com.alexthesis.crypto.helpers.KeySecret;

/**
 * Interface for retrieving and deserializing key secrets.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Retrieve secret values by secret ID</li>
 *   <li>Deserialize structured secret JSON into KeySecret records</li>
 *   <li>Handle retrieval errors gracefully</li>
 * </ul>
 *
 * <p>The provider does <b>not</b> contain cryptographic verification logic.
 * Parsing and caching are handled by separate layers.
 *
 * <p>Concrete implementations live in the Lambda modules (producer-lambda, consumer-lambda)
 * where AWS SDK dependencies are available.
 */
public interface KeyProvider {

    /**
     * Retrieves and deserializes a secret from storage.
     *
     * <p>The secret ID typically follows the naming structure:
     * <pre>
     *   thesis/{algorithm}/{stage}
     * </pre>
     * Examples:
     *   - thesis/hmac/current
     *   - thesis/rsa/previous
     *   - thesis/ecdsa/current
     *
     * @param secretId the secret ID or ARN
     * @return the deserialized KeySecret
     * @throws RuntimeException if retrieval or deserialization fails
     */
    KeySecret retrieveSecret(String secretId);

    /**
     * Constructs the standard secret ID from algorithm and stage.
     *
     * @param algorithm the algorithm name (hmac, rsa, ecdsa, etc.)
     * @param stage the key stage (current or previous)
     * @return the standard secret ID in thesis/{algorithm}/{stage} format
     */
    static String buildSecretId(String algorithm, String stage) {
        return "thesis/" + algorithm.toLowerCase() + "/" + stage.toLowerCase();
    }

    /**
     * Constructs a secondary secret ID from a base secret ID by replacing current/previous.
     *
     * @param baseSecretId the original secret ID (e.g., "thesis/rsa/current")
     * @param newStage the new stage to use (e.g., "previous")
     * @return the modified secret ID
     */
    static String transformSecretId(String baseSecretId, String newStage) {
        // Replace common stage patterns
        if (baseSecretId.contains("/current")) {
            return baseSecretId.replace("/current", "/" + newStage);
        } else if (baseSecretId.contains(":current")) {
            return baseSecretId.replace(":current", ":" + newStage);
        } else if (baseSecretId.endsWith("-current")) {
            return baseSecretId.replace("-current", "-" + newStage);
        } else {
            // Fallback: append stage to the end
            return baseSecretId + "/" + newStage;
        }
    }
}


