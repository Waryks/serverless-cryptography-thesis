package com.alexthesis.security.keys;

/**
 * Result of algorithm compatibility validation between key type and algorithm.
 *
 * <p>Prevents incorrect key usage such as attempting to use an RSA key for HMAC operations.
 */
public record KeyValidationResult(
        boolean valid,
        String algorithm,
        String keyMaterial,
        String errorMessage
) {

    /**
     * Creates a successful validation result.
     */
    public static KeyValidationResult success(String algorithm, String keyMaterial) {
        return new KeyValidationResult(true, algorithm, keyMaterial, null);
    }

    /**
     * Creates a failed validation result.
     */
    public static KeyValidationResult failure(String algorithm, String keyMaterial, String errorMessage) {
        return new KeyValidationResult(false, algorithm, keyMaterial, errorMessage);
    }

    /**
     * Validates that the algorithm and key material are compatible.
     *
     * @param algorithm the algorithm string (e.g., "RSA_PSS_SHA256")
     * @param keyMaterial the raw key material (Base64 for HMAC, PEM for asymmetric)
     * @return a validation result
     */
    public static KeyValidationResult validate(String algorithm, String keyMaterial) {
        if (algorithm == null || algorithm.isBlank()) {
            return failure(algorithm, keyMaterial, "Algorithm cannot be null or blank");
        }

        if (keyMaterial == null || keyMaterial.isBlank()) {
            return failure(algorithm, keyMaterial, "Key material cannot be null or blank");
        }

        // Basic format checks for different key types
        boolean hasHmacPrefix = algorithm.contains("HMAC");
        boolean hasRsaPrefix = algorithm.contains("RSA");
        boolean hasEcdsaPrefix = algorithm.contains("ECDSA");
        boolean hasPemHeader = keyMaterial.contains("BEGIN") || keyMaterial.contains("END");

        // HMAC keys should be base64, not PEM
        if (hasHmacPrefix && hasPemHeader) {
            return failure(algorithm, keyMaterial,
                    "HMAC algorithm requires Base64-encoded key material, not PEM");
        }

        // Asymmetric keys should have PEM headers
        if ((hasRsaPrefix || hasEcdsaPrefix) && !hasPemHeader) {
            return failure(algorithm, keyMaterial,
                    "Asymmetric algorithm (" + algorithm + ") requires PEM-encoded key material");
        }

        return success(algorithm, keyMaterial);
    }

    /**
     * Returns true if validation passed.
     */
    public boolean isValid() {
        return valid;
    }

    /**
     * Returns the error message if validation failed.
     */
    public String getErrorMessage() {
        return errorMessage;
    }
}

