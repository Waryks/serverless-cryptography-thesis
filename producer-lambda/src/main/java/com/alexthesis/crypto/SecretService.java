package com.alexthesis.crypto;

import com.alexthesis.crypto.helpers.KeySecret;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Retrieves and deserialises key secrets from AWS Secrets Manager.
 *
 * <p>Caching behaviour is controlled by {@code thesis.keys.cache.ttlSeconds}:
 * <ul>
 *   <li>{@code 0} — no cache; a fresh Secrets Manager call is made on every invocation (baseline)</li>
 *   <li>{@code >0} — TTL-based per-keyId in-memory cache; each secret is cached independently
 *       so that concurrent use of multiple keyIds never returns a stale entry for the wrong key
 *       (mitigation experiment)</li>
 * </ul>
 */
@ApplicationScoped
public class SecretService {

    private static final Logger log = Logger.getLogger(SecretService.class);

    private final SecretsManagerClient secretsManagerClient;
    private final ObjectMapper objectMapper;
    private final long cacheTtlSeconds;

    /** Per-keyId cache entries. Only populated when {@code cacheTtlSeconds > 0}. */
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    @Inject
    public SecretService(SecretsManagerClient secretsManagerClient,
                         ObjectMapper objectMapper,
                         @ConfigProperty(name = "thesis.keys.cache.ttlSeconds", defaultValue = "0")
                         long cacheTtlSeconds) {
        this.secretsManagerClient = secretsManagerClient;
        this.objectMapper = objectMapper;
        this.cacheTtlSeconds = cacheTtlSeconds;
    }

    /**
     * Returns the {@link KeySecret} stored under the given {@code keyId}.
     * The {@code keyId} is used directly as the Secrets Manager secret name or ARN.
     *
     * <p>If caching is enabled and the cached entry for this specific {@code keyId}
     * has not yet expired, the cached value is returned without a remote call.
     *
     * @param keyId the Secrets Manager secret name or ARN
     * @return the deserialised {@link KeySecret}
     * @throws RuntimeException if the remote call fails or JSON deserialisation fails
     */
    public KeySecret getSecret(String keyId) {
        if (cacheTtlSeconds > 0) {
            Optional<KeySecret> cached = getFromCacheIfValid(keyId);
            if (cached.isPresent()) {
                return cached.get();
            }
        }

        KeySecret secret = fetchFromSecretsManager(keyId);
        storeInCacheIfEnabled(keyId, secret);

        return secret;
    }

    /**
     * Returns the cached {@link KeySecret} for {@code keyId} if present and not expired.
     * Evicts the entry if it has expired.
     */
    private Optional<KeySecret> getFromCacheIfValid(String keyId) {
        CacheEntry entry = cache.get(keyId);
        if (entry == null) {
            return Optional.empty();
        }
        if (System.currentTimeMillis() < entry.expiryMs) {
            log.debugf("Cache hit for keyId: %s", keyId);
            return Optional.of(entry.secret);
        }
        log.debugf("Cache expired for keyId: %s — evicting", keyId);
        cache.remove(keyId);

        return Optional.empty();
    }

    /**
     * Fetches and deserialises the secret from Secrets Manager.
     *
     * @throws RuntimeException if the call fails or the JSON cannot be deserialised
     */
    private KeySecret fetchFromSecretsManager(String keyId) {
        log.debugf("Fetching secret from Secrets Manager for keyId: %s", keyId);
        String secretJson = secretsManagerClient.getSecretValue(
                GetSecretValueRequest.builder().secretId(keyId).build()
        ).secretString();
        try {
            return objectMapper.readValue(secretJson, KeySecret.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to deserialize secret JSON for keyId: " + keyId, e);
        }
    }

    /** Stores {@code secret} in the cache under {@code keyId} when caching is enabled. */
    private void storeInCacheIfEnabled(String keyId, KeySecret secret) {
        if (cacheTtlSeconds > 0) {
            cache.put(keyId, new CacheEntry(secret,
                    System.currentTimeMillis() + cacheTtlSeconds * 1000L));
        }
    }

    /** Immutable cache entry holding a secret and its absolute expiry timestamp. */
    private record CacheEntry(KeySecret secret, long expiryMs) {}
}
