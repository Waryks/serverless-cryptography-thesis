package com.alexthesis.security.keys;

import com.alexthesis.crypto.helpers.KeySecret;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class KeyProviderTest {

    @Test
    void buildSecretId_CreatesStandardSecretIdFormat() {
        // Act
        String secretId = KeyProvider.buildSecretId("HMAC", "current");

        // Assert
        assertEquals("thesis/hmac/current", secretId);
    }

    @Test
    void transformSecretId_ReplacesCurrentWithPrevious_SlashFormat() {
        // Act
        String transformed = KeyProvider.transformSecretId("thesis/rsa/current", "previous");

        // Assert
        assertEquals("thesis/rsa/previous", transformed);
    }

    @Test
    void transformSecretId_ReplacesCurrentWithPrevious_ColonFormat() {
        // Act
        String transformed = KeyProvider.transformSecretId("thesis:rsa:current", "previous");

        // Assert
        assertEquals("thesis:rsa:previous", transformed);
    }

    @Test
    void transformSecretId_ReplacesCurrentWithPrevious_DashFormat() {
        // Act
        String transformed = KeyProvider.transformSecretId("thesis-rsa-current", "previous");

        // Assert
        assertEquals("thesis-rsa-previous", transformed);
    }
}


