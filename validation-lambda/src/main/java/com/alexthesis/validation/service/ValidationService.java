package com.alexthesis.validation.service;

import com.alexthesis.crypto.helpers.KeySecret;
import com.alexthesis.messaging.AuditReason;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.alexthesis.validation.checks.DedupStore;
import com.alexthesis.validation.checks.ReplayChecker;
import com.alexthesis.validation.crypto.SignatureVerifier;
import com.alexthesis.validation.crypto.SecretService;
import com.alexthesis.validation.routing.ValidationRouter;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

/**
 * Core business logic for the validation Lambda.
 * Orchestrates deserialization, signature verification, replay checking, deduplication,
 * and routing of events to accepted or rejected queues.
 *
 * <p>This service is the decision point for the validation pipeline. It does NOT persist
 * events directly to DynamoDB. Instead, it routes decisions to downstream queues where:
 * - Accepted events are persisted by the Persistence Lambda
 * - Rejected events are logged by the Audit Lambda
 *
 * <p>Security rejections (invalid signature, replay, duplicate) do NOT throw exceptions.
 * Only infrastructure failures (Secrets Manager unavailable, SQS down, etc.) throw.
 */
@ApplicationScoped
public class ValidationService {

    private static final Logger log = Logger.getLogger(ValidationService.class);

    private final ObjectMapper objectMapper;
    private final SecretService secretService;
    private final SignatureVerifier signatureVerifier;
    private final ReplayChecker replayChecker;
    private final DedupStore dedupStore;
    private final ValidationRouter router;

    @Inject
    public ValidationService(
            ObjectMapper objectMapper,
            SecretService secretService,
            SignatureVerifier signatureVerifier,
            ReplayChecker replayChecker,
            DedupStore dedupStore,
            ValidationRouter router) {
        this.objectMapper = objectMapper;
        this.secretService = secretService;
        this.signatureVerifier = signatureVerifier;
        this.replayChecker = replayChecker;
        this.dedupStore = dedupStore;
        this.router = router;
    }

    /**
     * Processes a single SQS message body:
     * <ol>
     *   <li>Deserializes the JSON into a {@link SignedEvent}</li>
     *   <li>Validates basic event structure</li>
     *   <li>Loads the key from Secrets Manager using {@link SignedContent#keyId()}</li>
     *   <li>Verifies the signature</li>
     *   <li>Checks replay window if enabled</li>
     *   <li>Checks deduplication if enabled</li>
     *   <li>Routes event to appropriate queue</li>
     * </ol>
     *
     * <p>Security rejections are caught and routed to the rejected queue gracefully.
     * Only infrastructure failures propagate as exceptions.
     *
     * @param messageBodyJson raw SQS message body
     * @throws RuntimeException only if an infrastructure error occurs that should be retried
     *         (e.g., Secrets Manager unavailable, SQS publish failure)
     */
    public void processMessage(String messageBodyJson) {
        try {
            // Step 1: Deserialize event
            SignedEvent event = deserializeEvent(messageBodyJson);
            SignedContent content = event.content();

            // Step 2: Validate basic structure
            validateStructure(content);

            // Step 3: Load key (may throw infrastructure exception)
            KeySecret secret = secretService.getSecret(content.keyId());

            // Step 4: Verify signature
            if (!signatureVerifier.verifySignature(content, event.signatureB64(), secret)) {
                routeRejected(event, AuditReason.INVALID_SIGNATURE, "Signature verification failed");
                return;
            }

            // Step 5: Check replay window
            if (!replayChecker.isWithinReplayWindow(content)) {
                routeRejected(event, AuditReason.EXPIRED, "Event outside replay window");
                return;
            }

            // Step 6: Check deduplication
            if (!dedupStore.isNewEvent(content)) {
                routeRejected(event, AuditReason.REPLAY_DETECTED, "Duplicate event detected");
                return;
            }

            // Step 7: Route accepted event
            router.routeAccepted(event);
            log.infof("Successfully validated and routed event %s", content.eventId());

        } catch (SecurityRejectionException e) {
            // Security rejection already routed; no further action needed
            log.warnf("Security rejection: %s", e.getReason());
        } catch (Exception e) {
            // Infrastructure failure: let it propagate so SQS will retry
            log.errorf(e, "Infrastructure failure processing message");
            throw new RuntimeException("Infrastructure failure during validation", e);
        }
    }

    /**
     * Deserializes the SQS message body into a {@link SignedEvent}.
     *
     * <p>If deserialization fails, the event is routed to the rejected queue
     * with no original event provided (since we cannot parse it).
     *
     * @param messageBodyJson raw SQS message body
     * @return the deserialized SignedEvent
     * @throws SecurityRejectionException if deserialization fails
     */
    private SignedEvent deserializeEvent(String messageBodyJson) {
        try {
            return objectMapper.readValue(messageBodyJson, SignedEvent.class);
        } catch (Exception e) {
            log.warnf(e, "Failed to deserialize SQS message");
            throw new SecurityRejectionException(
                    AuditReason.DESERIALIZATION_ERROR,
                    "Failed to deserialize event: " + e.getMessage()
            );
        }
    }

    /**
     * Validates that the event has all required fields.
     *
     * @param content the SignedContent to validate
     * @throws SecurityRejectionException if required fields are missing
     */
    private void validateStructure(SignedContent content) {
        if (content.eventId() == null || content.eventId().isBlank()) {
            throw new SecurityRejectionException(
                    AuditReason.DESERIALIZATION_ERROR,
                    "Missing or empty eventId"
            );
        }
        if (content.algorithm() == null) {
            throw new SecurityRejectionException(
                    AuditReason.DESERIALIZATION_ERROR,
                    "Missing algorithm"
            );
        }
        if (content.keyId() == null || content.keyId().isBlank()) {
            throw new SecurityRejectionException(
                    AuditReason.DESERIALIZATION_ERROR,
                    "Missing or empty keyId"
            );
        }
        if (content.payload() == null) {
            throw new SecurityRejectionException(
                    AuditReason.DESERIALIZATION_ERROR,
                    "Missing payload"
            );
        }
    }

    /**
     * Routes a rejection decision to the rejected queue.
     * Catches any exceptions to avoid propagating routing failures.
     *
     * @param event the original SignedEvent
     * @param reason the reason for rejection
     * @param message descriptive message
     */
    private void routeRejected(SignedEvent event, AuditReason reason, String message) {
        try {
            router.routeRejected(event, reason, message);
        } catch (Exception e) {
            // Log but do not throw: we've already made the security decision
            log.errorf(e, "Failed to route rejected event to rejected queue (reason=%s)", reason);
            // Note: In production, we might want to write to a dead letter queue or retry
        }
    }

    /**
     * Represents a security policy rejection during validation.
     *
     * <p>This exception is caught by the handler to distinguish between
     * security rejections (which should not cause SQS retry) and infrastructure
     * failures (which should cause SQS retry).
     */
    public static class SecurityRejectionException extends RuntimeException {
        private final AuditReason reason;

        public SecurityRejectionException(AuditReason reason, String message) {
            super(message);
            this.reason = reason;
        }

        public AuditReason getReason() {
            return reason;
        }
    }
}



