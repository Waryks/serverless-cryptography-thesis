package com.alexthesis.security.keys;

import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class KeyCacheTest {

    @Test
    void keyCache_Disabled_WhenTtlIsZero() {
        // Arrange
        KeyCache cache = new KeyCache(0);

        // Assert
        assertFalse(cache.isEnabled());
    }

    @Test
    void keyCache_Enabled_WhenTtlIsPositive() {
        // Arrange
        KeyCache cache = new KeyCache(1000);

        // Assert
        assertTrue(cache.isEnabled());
    }

    @Test
    void get_ReturnsEmpty_WhenCacheDisabled() {
        // Arrange
        KeyCache cache = new KeyCache(0);
        String keyId = "test-key";

        // Act
        Optional<ParsedKey> result = cache.get(keyId);

        // Assert
        assertTrue(result.isEmpty());
    }

    @Test
    void put_StoresAndRetrieves_WhenCacheEnabled() throws Exception {
        // Arrange
        KeyCache cache = new KeyCache(10000); // 10 second TTL
        String keyId = "test-key";

        KeyDescriptor descriptor = KeyDescriptor.current("test-key", "HMAC_SHA256", "test");
        byte[] keyBytes = "test-secret-key-material".getBytes();
        var secretKey = new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA256");
        ParsedKey parsedKey = new ParsedKey(descriptor, Base64.getEncoder().encodeToString(keyBytes), secretKey);

        // Act
        cache.put(keyId, parsedKey);
        Optional<ParsedKey> retrieved = cache.get(keyId);

        // Assert
        assertTrue(retrieved.isPresent());
        assertEquals(keyId, retrieved.get().descriptor().keyId());
    }

    @Test
    void get_ReturnsEmpty_WhenEntryExpired() throws Exception {
        // Arrange
        KeyCache cache = new KeyCache(100); // 100ms TTL
        String keyId = "test-key";

        KeyDescriptor descriptor = KeyDescriptor.current("test-key", "HMAC_SHA256", "test");
        byte[] keyBytes = "test-secret-key-material".getBytes();
        var secretKey = new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA256");
        ParsedKey parsedKey = new ParsedKey(descriptor, Base64.getEncoder().encodeToString(keyBytes), secretKey);

        cache.put(keyId, parsedKey);

        // Act
        Thread.sleep(150); // Wait for expiry
        Optional<ParsedKey> retrieved = cache.get(keyId);

        // Assert
        assertTrue(retrieved.isEmpty());
    }

    @Test
    void invalidate_RemovesEntry() throws Exception {
        // Arrange
        KeyCache cache = new KeyCache(10000);
        String keyId = "test-key";

        KeyDescriptor descriptor = KeyDescriptor.current("test-key", "HMAC_SHA256", "test");
        byte[] keyBytes = "test-secret-key-material".getBytes();
        var secretKey = new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA256");
        ParsedKey parsedKey = new ParsedKey(descriptor, Base64.getEncoder().encodeToString(keyBytes), secretKey);

        cache.put(keyId, parsedKey);

        // Act
        cache.invalidate(keyId);
        Optional<ParsedKey> retrieved = cache.get(keyId);

        // Assert
        assertTrue(retrieved.isEmpty());
    }

    @Test
    void clear_RemovesAllEntries() throws Exception {
        // Arrange
        KeyCache cache = new KeyCache(10000);
        KeyDescriptor descriptor = KeyDescriptor.current("test-key", "HMAC_SHA256", "test");
        byte[] keyBytes = "test-secret-key-material".getBytes();
        var secretKey = new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA256");
        ParsedKey parsedKey = new ParsedKey(descriptor, Base64.getEncoder().encodeToString(keyBytes), secretKey);

        cache.put("key1", parsedKey);
        cache.put("key2", parsedKey);

        // Act
        cache.clear();

        // Assert
        assertEquals(0, cache.size());
    }

    @Test
    void size_ReturnsCorrectCount() throws Exception {
        // Arrange
        KeyCache cache = new KeyCache(10000);
        KeyDescriptor descriptor = KeyDescriptor.current("test-key", "HMAC_SHA256", "test");
        byte[] keyBytes = "test-secret-key-material".getBytes();
        var secretKey = new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA256");
        ParsedKey parsedKey = new ParsedKey(descriptor, Base64.getEncoder().encodeToString(keyBytes), secretKey);

        // Act
        cache.put("key1", parsedKey);
        cache.put("key2", parsedKey);

        // Assert
        assertEquals(2, cache.size());
    }
}

