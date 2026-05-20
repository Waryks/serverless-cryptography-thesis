package com.alexthesis.crypto.keymanagement;

import com.alexthesis.crypto.helpers.KeySecret;
import com.alexthesis.security.keys.KeyProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

/**
 * AWS Secrets Manager implementation of the KeyProvider interface for the Consumer Lambda.
 *
 * <p>Retrieves and deserializes cryptographic key secrets from AWS Secrets Manager.
 */
@ApplicationScoped
public class SecretsManagerKeyProvider implements KeyProvider {

    private static final Logger log = Logger.getLogger(SecretsManagerKeyProvider.class);

    private final SecretsManagerClient secretsManagerClient;
    private final ObjectMapper objectMapper;

    @Inject
    public SecretsManagerKeyProvider(SecretsManagerClient secretsManagerClient, ObjectMapper objectMapper) {
        this.secretsManagerClient = secretsManagerClient;
        this.objectMapper = objectMapper;
    }

    @Override
    public KeySecret retrieveSecret(String secretId) {
        log.debugf("Retrieving secret from Secrets Manager: %s", secretId);

        try {
            String secretJson = secretsManagerClient.getSecretValue(
                    GetSecretValueRequest.builder().secretId(secretId).build()
            ).secretString();

            KeySecret secret = objectMapper.readValue(secretJson, KeySecret.class);
            log.debugf("Successfully retrieved secret: %s (keyId=%s, algorithm=%s)",
                    secretId, secret.keyId(), secret.algorithm());
            return secret;
        } catch (Exception e) {
            log.errorf(e, "Failed to retrieve or deserialize secret: %s", secretId);
            throw new RuntimeException("Secret retrieval failed for: " + secretId, e);
        }
    }
}

