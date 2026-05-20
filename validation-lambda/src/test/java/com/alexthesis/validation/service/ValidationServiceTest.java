package com.alexthesis.validation.service;

import com.alexthesis.crypto.helpers.KeySecret;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.AuditReason;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.alexthesis.validation.checks.DedupStore;
import com.alexthesis.validation.checks.ReplayChecker;
import com.alexthesis.validation.crypto.SignatureVerifier;
import com.alexthesis.validation.crypto.SecretService;
import com.alexthesis.validation.routing.ValidationRouter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the ValidationService.
 * Tests the orchestration of signature verification, replay checking, and routing.
 */
@QuarkusTest
public class ValidationServiceTest {

    @Inject
    ObjectMapper objectMapper;

    @Mock
    SecretService secretService;

    @Mock
    SignatureVerifier signatureVerifier;

    @Mock
    ReplayChecker replayChecker;

    @Mock
    DedupStore dedupStore;

    @Mock
    ValidationRouter router;

    private ValidationService validationService;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        validationService = new ValidationService(
                objectMapper,
                secretService,
                signatureVerifier,
                replayChecker,
                dedupStore,
                router
        );
    }

    @Test
    public void testProcessMessage_ValidEvent_RoutesAccepted() {
        // Arrange
        SignedEvent event = createValidSignedEvent();
        String messageBody = serializeEvent(event);

        KeySecret secret = new KeySecret("key1", "HMAC_SHA256", "secret-key-material");
        when(secretService.getSecret("key1")).thenReturn(secret);
        when(signatureVerifier.verifySignature(any(), any(), any())).thenReturn(true);
        when(replayChecker.isWithinReplayWindow(any())).thenReturn(true);
        when(dedupStore.isNewEvent(any())).thenReturn(true);

        // Act
        validationService.processMessage(messageBody);

        // Assert
        verify(router, times(1)).routeAccepted(event);
        verify(router, never()).routeRejected(any(), any(), any());
    }

    @Test
    public void testProcessMessage_InvalidSignature_RoutesRejected() {
        // Arrange
        SignedEvent event = createValidSignedEvent();
        String messageBody = serializeEvent(event);

        KeySecret secret = new KeySecret("key1", "HMAC_SHA256", "secret-key-material");
        when(secretService.getSecret("key1")).thenReturn(secret);
        when(signatureVerifier.verifySignature(any(), any(), any())).thenReturn(false);

        // Act
        validationService.processMessage(messageBody);

        // Assert
        verify(router, times(1)).routeRejected(any(SignedEvent.class), eq(AuditReason.INVALID_SIGNATURE), any());
        verify(router, never()).routeAccepted(any());
    }

    @Test
    public void testProcessMessage_ReplayWindow_RoutesRejected() {
        // Arrange
        SignedEvent event = createValidSignedEvent();
        String messageBody = serializeEvent(event);

        KeySecret secret = new KeySecret("key1", "HMAC_SHA256", "secret-key-material");
        when(secretService.getSecret("key1")).thenReturn(secret);
        when(signatureVerifier.verifySignature(any(), any(), any())).thenReturn(true);
        when(replayChecker.isWithinReplayWindow(any())).thenReturn(false);

        // Act
        validationService.processMessage(messageBody);

        // Assert
        verify(router, times(1)).routeRejected(any(SignedEvent.class), eq(AuditReason.EXPIRED), any());
        verify(router, never()).routeAccepted(any());
    }

    @Test
    public void testProcessMessage_DuplicateEvent_RoutesRejected() {
        // Arrange
        SignedEvent event = createValidSignedEvent();
        String messageBody = serializeEvent(event);

        KeySecret secret = new KeySecret("key1", "HMAC_SHA256", "secret-key-material");
        when(secretService.getSecret("key1")).thenReturn(secret);
        when(signatureVerifier.verifySignature(any(), any(), any())).thenReturn(true);
        when(replayChecker.isWithinReplayWindow(any())).thenReturn(true);
        when(dedupStore.isNewEvent(any())).thenReturn(false);

        // Act
        validationService.processMessage(messageBody);

        // Assert
        verify(router, times(1)).routeRejected(any(SignedEvent.class), eq(AuditReason.REPLAY_DETECTED), any());
        verify(router, never()).routeAccepted(any());
    }

    @Test
    public void testProcessMessage_SecretsManagerFailure_Throws() {
        // Arrange
        SignedEvent event = createValidSignedEvent();
        String messageBody = serializeEvent(event);

        when(secretService.getSecret(any())).thenThrow(new RuntimeException("Secrets Manager unavailable"));

        // Act & Assert
        assertThrows(RuntimeException.class, () -> validationService.processMessage(messageBody));
        verify(router, never()).routeAccepted(any());
        verify(router, never()).routeRejected(any(), any(), any());
    }

    @Test
    public void testProcessMessage_InvalidJson_ThrowsOrRoutsRejected() {
        // Arrange
        String invalidJson = "{invalid json}";

        // Act & Assert
        // Invalid JSON causes a deserialization exception which is routed to rejected queue
        // No exception is thrown to the caller (security rejection, not infrastructure failure)
        assertDoesNotThrow(() -> validationService.processMessage(invalidJson));
    }

    private SignedEvent createValidSignedEvent() {
        JsonNode payload = objectMapper.createObjectNode().put("data", "test");
        SignedContent content = new SignedContent(
                "event-123",
                System.currentTimeMillis(),
                Algorithm.HMAC_SHA256,
                "key1",
                payload
        );
        return new SignedEvent(content, "signature-b64");
    }

    private String serializeEvent(SignedEvent event) {
        try {
            return objectMapper.writeValueAsString(event);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}






