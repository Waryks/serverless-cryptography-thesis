package com.alexthesis.security.keys;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyValidationResultTest {

    @Test
    void validate_Success_ForHmacBase64Key() {
        // Act
        KeyValidationResult result = KeyValidationResult.validate("HMAC_SHA256", "Y2Fub25pY2Fsa2V5");

        // Assert
        assertTrue(result.isValid());
        assertNull(result.getErrorMessage());
    }

    @Test
    void validate_Failure_ForHmacWithPemHeader() {
        // Act
        KeyValidationResult result = KeyValidationResult.validate("HMAC_SHA256", "-----BEGIN PRIVATE KEY-----");

        // Assert
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("HMAC"));
    }

    @Test
    void validate_Failure_ForRsaWithoutPem() {
        // Act
        KeyValidationResult result = KeyValidationResult.validate("RSA_PSS_SHA256", "Y2Fub25pY2Fsa2V5");

        // Assert
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("PEM"));
    }

    @Test
    void validate_Success_ForRsaWithPem() {
        // Act
        KeyValidationResult result = KeyValidationResult.validate("RSA_PSS_SHA256", "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----");

        // Assert
        assertTrue(result.isValid());
    }

    @Test
    void validate_Failure_ForNullAlgorithm() {
        // Act
        KeyValidationResult result = KeyValidationResult.validate(null, "somekey");

        // Assert
        assertFalse(result.isValid());
    }

    @Test
    void validate_Failure_ForNullKeyMaterial() {
        // Act
        KeyValidationResult result = KeyValidationResult.validate("HMAC_SHA256", null);

        // Assert
        assertFalse(result.isValid());
    }
}

