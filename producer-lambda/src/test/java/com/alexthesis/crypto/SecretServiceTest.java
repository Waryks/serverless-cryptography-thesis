package com.alexthesis.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link SecretService}.
 * AWS Secrets Manager is mocked — no network calls are made.
 */
@ExtendWith(MockitoExtension.class)
class SecretServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String KEY_ID = "my-key-id";
    private static final String SECRET_JSON =
            "{\"keyId\":\"my-key-id\",\"algorithm\":\"HMAC_SHA256\",\"keyMaterial\":\"c2VjcmV0\"}";

    @Mock
    SecretsManagerClient secretsManagerClient;

    @Test
    void getSecret_noCache_fetchesFromSecretsManager() {
        stubResponse(SECRET_JSON);
        SecretService service = new SecretService(secretsManagerClient, MAPPER, 0);

        KeySecret result = service.getSecret(KEY_ID);

        assertThat(result.keyId()).isEqualTo(KEY_ID);
        assertThat(result.algorithm()).isEqualTo("HMAC_SHA256");
        assertThat(result.keyMaterial()).isEqualTo("c2VjcmV0");
        verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
    }

    @Test
    void getSecret_noCache_fetchesOnEveryCall() {
        stubResponse(SECRET_JSON);
        SecretService service = new SecretService(secretsManagerClient, MAPPER, 0);

        service.getSecret(KEY_ID);
        service.getSecret(KEY_ID);

        // No caching — two calls must produce two remote fetches
        verify(secretsManagerClient, times(2)).getSecretValue(any(GetSecretValueRequest.class));
    }

    @Test
    void getSecret_invalidJson_throwsRuntimeException() {
        stubResponse("not-valid-json");
        SecretService service = new SecretService(secretsManagerClient, MAPPER, 0);

        assertThatThrownBy(() -> service.getSecret(KEY_ID))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining(KEY_ID);
    }

    @Test
    void getSecret_withCache_secondCallReturnsCachedValue() {
        stubResponse(SECRET_JSON);
        SecretService service = new SecretService(secretsManagerClient, MAPPER, 60);

        KeySecret first  = service.getSecret(KEY_ID);
        KeySecret second = service.getSecret(KEY_ID);

        assertThat(first).isEqualTo(second);
        // Only one remote call — second hit came from cache
        verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
    }

    @Test
    void getSecret_withCache_fetchesAgainAfterTtlExpiry() throws InterruptedException {
        stubResponse(SECRET_JSON);
        // TTL of 0 seconds effectively expires immediately
        SecretService service = new SecretService(secretsManagerClient, MAPPER, 1);

        service.getSecret(KEY_ID);
        // Wait for the 1-second TTL to expire
        Thread.sleep(1100);
        service.getSecret(KEY_ID);

        verify(secretsManagerClient, times(2)).getSecretValue(any(GetSecretValueRequest.class));
    }

    private void stubResponse(String json) {
        GetSecretValueResponse response = GetSecretValueResponse.builder()
                .secretString(json)
                .build();
        when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                .thenReturn(response);
    }
}

