package com.alexthesis.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

/**
 * Retrieves and deserialises key secrets from AWS Secrets Manager.
 *
 * <p>Caching behaviour is controlled by {@code thesis.keys.cache.ttlSeconds}:
 * <ul>
 *   <li>{@code 0} — no cache; a fresh Secrets Manager call is made on every invocation (baseline experiment)</li>
 *   <li>{@code >0} — TTL-based in-memory cache; the secret is reused until the TTL expires (mitigation experiment)</li>
 * </ul>
 */
@ApplicationScoped
public class SecretService {

    private static final Logger log = Logger.getLogger(SecretService.class);

    private final SecretsManagerClient secretsManagerClient;
    private final ObjectMapper objectMapper;
    private final long cacheTtlSeconds;

    // volatile ensures cross-invocation visibility within the same warm container
    private volatile KeySecret cachedSecret;
    private volatile long cacheExpiryMs = 0;

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
     * <p>If caching is enabled and the cached entry has not yet expired, the cached
     * value is returned without making a remote call.
     *
     * @param keyId the Secrets Manager secret name or ARN, taken from {@link com.alexthesis.messaging.SignedContent#keyId()}
     * @return the deserialised {@link KeySecret}
     * @throws RuntimeException if the remote call fails or the secret JSON cannot be deserialised
     */
    public KeySecret getSecret(String keyId) {
        if (cacheTtlSeconds > 0 && cachedSecret != null && System.currentTimeMillis() < cacheExpiryMs) {
            log.debug("Returning cached secret for keyId: " + keyId);
            return cachedSecret;
        }

        log.debug("Fetching secret from Secrets Manager for keyId: " + keyId);
        String secretJson = secretsManagerClient.getSecretValue(
                GetSecretValueRequest.builder().secretId(keyId).build()
        ).secretString();

        try {
            KeySecret secret = objectMapper.readValue(secretJson, KeySecret.class);
            if (cacheTtlSeconds > 0) {
                cachedSecret = secret;
                cacheExpiryMs = System.currentTimeMillis() + cacheTtlSeconds * 1000L;
            }
            return secret;
        } catch (Exception e) {
            throw new RuntimeException("Failed to deserialize secret JSON for keyId: " + keyId, e);
        }
    }
}

