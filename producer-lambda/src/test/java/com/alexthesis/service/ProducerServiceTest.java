package com.alexthesis.service;

import com.alexthesis.crypto.KeySecret;
import com.alexthesis.crypto.SecretService;
import com.alexthesis.crypto.SignatureService;
import com.alexthesis.events.EventPublisher;
import com.alexthesis.lambda.ProducerResponse;
import com.alexthesis.lambda.ProducerService;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link ProducerService}.
 * All collaborators (SecretService, SignatureService, EventPublisher) are mocked.
 */
@ExtendWith(MockitoExtension.class)
class ProducerServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Mock SecretService secretService;
    @Mock SignatureService signatureService;
    @Mock EventPublisher publisher;

    private ProducerService producerService;

    @BeforeEach
    void setUp() {
        producerService = new ProducerService(publisher, secretService, signatureService);
    }

    @Test
    void processEvent_returnsResponseWithCorrectEventId() {
        SignedEvent input = buildEvent("evt-42", Algorithm.HMAC_SHA256, "key-1");
        stubCollaborators("key-1", "sig-abc");

        ProducerResponse response = producerService.processEvent(input);

        assertThat(response.eventId()).isEqualTo("evt-42");
    }

    @Test
    void processEvent_durationIsNonNegative() {
        SignedEvent input = buildEvent("evt-1", Algorithm.HMAC_SHA256, "key-1");
        stubCollaborators("key-1", "sig");

        ProducerResponse response = producerService.processEvent(input);

        assertThat(response.durationMs()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void processEvent_publishesEventWithSignatureFromSignatureService() {
        SignedEvent input = buildEvent("evt-1", Algorithm.HMAC_SHA256, "key-1");
        stubCollaborators("key-1", "my-signature-b64");

        producerService.processEvent(input);

        ArgumentCaptor<SignedEvent> captor = ArgumentCaptor.forClass(SignedEvent.class);
        verify(publisher).publish(captor.capture());
        assertThat(captor.getValue().signatureB64()).isEqualTo("my-signature-b64");
    }

    @Test
    void processEvent_publishesEventWithOriginalContent() {
        SignedEvent input = buildEvent("evt-1", Algorithm.HMAC_SHA256, "key-1");
        stubCollaborators("key-1", "sig");

        producerService.processEvent(input);

        ArgumentCaptor<SignedEvent> captor = ArgumentCaptor.forClass(SignedEvent.class);
        verify(publisher).publish(captor.capture());
        assertThat(captor.getValue().content()).isEqualTo(input.content());
    }

    @Test
    void processEvent_fetchesSecretUsingKeyIdFromContent() {
        SignedEvent input = buildEvent("evt-1", Algorithm.HMAC_SHA256, "the-key-id");
        stubCollaborators("the-key-id", "sig");

        producerService.processEvent(input);

        verify(secretService).getSecret("the-key-id");
    }

    @Test
    void processEvent_secretServiceThrows_propagatesException() {
        SignedEvent input = buildEvent("evt-1", Algorithm.HMAC_SHA256, "key-1");
        when(secretService.getSecret(any())).thenThrow(new RuntimeException("Secrets Manager unavailable"));

        assertThatThrownBy(() -> producerService.processEvent(input))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Secrets Manager unavailable");
    }

    @Test
    void processEvent_signatureServiceThrows_propagatesException() {
        SignedEvent input = buildEvent("evt-1", Algorithm.HMAC_SHA256, "key-1");
        KeySecret secret = new KeySecret("key-1", "HMAC_SHA256", "dGVzdA==");
        when(secretService.getSecret("key-1")).thenReturn(secret);
        when(signatureService.sign(any(), any())).thenThrow(new RuntimeException("Signing failed"));

        assertThatThrownBy(() -> producerService.processEvent(input))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Signing failed");
    }

    private SignedEvent buildEvent(String eventId, Algorithm algorithm, String keyId) {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("data", "value");
        SignedContent content = new SignedContent(eventId, 1_700_000_000_000L, algorithm, keyId, payload);
        return new SignedEvent(content, null);
    }

    private void stubCollaborators(String keyId, String signature) {
        KeySecret secret = new KeySecret(keyId, "HMAC_SHA256", "dGVzdA==");
        when(secretService.getSecret(keyId)).thenReturn(secret);
        when(signatureService.sign(any(), any())).thenReturn(signature);
    }
}

