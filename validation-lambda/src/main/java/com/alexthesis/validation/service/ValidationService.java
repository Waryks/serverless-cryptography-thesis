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
import com.alexthesis.validation.policy.PolicyEngine;
import com.alexthesis.validation.policy.PolicyValidationResult;
import com.alexthesis.validation.policy.SecurityPolicy;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.alexthesis.metrics.ColdStartTracker;
import com.alexthesis.metrics.MetricsContext;
import com.alexthesis.metrics.TimingStage;
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
    private final PolicyEngine policyEngine;

    @Inject
    public ValidationService(
            ObjectMapper objectMapper,
            SecretService secretService,
            SignatureVerifier signatureVerifier,
            ReplayChecker replayChecker,
            DedupStore dedupStore,
            ValidationRouter router,
            PolicyEngine policyEngine) {
        this.objectMapper = objectMapper;
        this.secretService = secretService;
        this.signatureVerifier = signatureVerifier;
        this.replayChecker = replayChecker;
        this.dedupStore = dedupStore;
        this.router = router;
        this.policyEngine = policyEngine;
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
            ValidationDecision decision = decide(messageBodyJson);

            if (decision instanceof ValidationDecision.Accepted accepted) {
                router.routeAccepted(accepted.event());
                log.infof("Successfully validated and routed event %s", accepted.event().content().eventId());
            } else if (decision instanceof ValidationDecision.Rejected rejected) {
                routeRejected(rejected.originalEvent(), rejected.reason(), rejected.message());
            }
        } catch (Exception e) {
            // Infrastructure failure: let it propagate so SQS will retry
            log.errorf(e, "Infrastructure failure processing message");
            throw new RuntimeException("Infrastructure failure during validation", e);
        }
    }

    private ValidationDecision decide(String messageBodyJson) {
        // Create a metrics context if we can determine an eventId during deserialization.
        SignedEvent event = deserializeEvent(messageBodyJson);
        if (event == null || event.content() == null) {
            return ValidationDecision.rejected(null, AuditReason.DESERIALIZATION_ERROR, "Failed to deserialize event");
        }

        SignedContent content = event.content();

        MetricsContext ctx = MetricsContext.create("validation", content.eventId(), ColdStartTracker.isColdStartAndMark("validation"));
        try (ctx) {
            ctx.start(TimingStage.LAMBDA_HANDLER);

            String structureError = validateStructure(content, event.signatureB64());
            if (structureError != null) {
                ctx.stop(TimingStage.LAMBDA_HANDLER);
                return ValidationDecision.rejected(event, AuditReason.DESERIALIZATION_ERROR, structureError);
            }

            ctx.start(TimingStage.POLICY_LOADING);
            PolicyValidationResult policyResult = policyEngine.evaluate(content);
            ctx.stop(TimingStage.POLICY_LOADING);

            if (!policyResult.allowed()) {
                ctx.stop(TimingStage.LAMBDA_HANDLER);
                return ValidationDecision.rejected(event, policyResult.rejectionReason(), policyResult.rejectionMessage());
            }

            SecurityPolicy policy = policyResult.policy();

            ctx.start(TimingStage.KEY_LOADING);
            KeySecret secret = secretService.getSecret(content.keyId());
            ctx.stop(TimingStage.KEY_LOADING);

            ctx.start(TimingStage.SIGNATURE_VERIFICATION);
            boolean signatureValid = signatureVerifier.verifySignature(content, event.signatureB64(), secret);
            ctx.stop(TimingStage.SIGNATURE_VERIFICATION);

            if (!signatureValid && policy.allowPreviousKey()) {
                String previousKeyId = policyEngine.resolvePreviousKeyId(content.keyId());
                if (!previousKeyId.equals(content.keyId())) {
                    ctx.start(TimingStage.KEY_LOADING);
                    KeySecret previousSecret = secretService.getSecret(previousKeyId);
                    ctx.stop(TimingStage.KEY_LOADING);

                    ctx.start(TimingStage.SIGNATURE_VERIFICATION);
                    signatureValid = signatureVerifier.verifySignature(content, event.signatureB64(), previousSecret);
                    ctx.stop(TimingStage.SIGNATURE_VERIFICATION);
                }
            }

            if (!signatureValid) {
                ctx.stop(TimingStage.LAMBDA_HANDLER);
                return ValidationDecision.rejected(
                        event,
                        policy.allowPreviousKey() ? AuditReason.UNKNOWN_KEY : AuditReason.INVALID_SIGNATURE,
                        policy.allowPreviousKey()
                                ? "Signature verification failed with current and previous key"
                                : "Signature verification failed"
                );
            }

            if (policy.replayCheckEnabled()) {
                ctx.start(TimingStage.REPLAY_CHECK);
            }
            if (policy.replayCheckEnabled() && !replayChecker.isWithinReplayWindow(content, policy.replayWindowMs())) {
                ctx.stop(TimingStage.REPLAY_CHECK);
                ctx.stop(TimingStage.LAMBDA_HANDLER);
                return ValidationDecision.rejected(event, AuditReason.EXPIRED, "Event outside replay window");
            }
            if (policy.replayCheckEnabled()) {
                ctx.stop(TimingStage.REPLAY_CHECK);
            }

            if (policy.dedupEnabled()) {
                ctx.start(TimingStage.DEDUP_CHECK);
            }
            if (policy.dedupEnabled() && !dedupStore.isNewEvent(content)) {
                ctx.stop(TimingStage.DEDUP_CHECK);
                ctx.stop(TimingStage.LAMBDA_HANDLER);
                return ValidationDecision.rejected(event, AuditReason.REPLAY_DETECTED, "Duplicate event detected");
            }
            if (policy.dedupEnabled()) {
                ctx.stop(TimingStage.DEDUP_CHECK);
            }

            ctx.stop(TimingStage.LAMBDA_HANDLER);

            // Emit snapshot to logs for collection
            ctx.snapshot().ifPresent(s -> System.out.println(s.toJson()));

            return ValidationDecision.accepted(event);
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
     */
    private SignedEvent deserializeEvent(String messageBodyJson) {
        try {
            return objectMapper.readValue(messageBodyJson, SignedEvent.class);
        } catch (Exception e) {
            log.warnf(e, "Failed to deserialize SQS message");
            return null;
        }
    }

    /**
     * Validates that the event has all required fields.
     *
     * @param content the SignedContent to validate
     * @param signatureB64 the Base64 signature to validate
     * @return a rejection message if required fields are missing, otherwise {@code null}
     */
    private String validateStructure(SignedContent content, String signatureB64) {
        if (content.eventId() == null || content.eventId().isBlank()) {
            return "Missing or empty eventId";
        }
        if (content.algorithm() == null) {
            return "Missing algorithm";
        }
        if (content.keyId() == null || content.keyId().isBlank()) {
            return "Missing or empty keyId";
        }
        if (content.payload() == null) {
            return "Missing payload";
        }
        if (signatureB64 == null || signatureB64.isBlank()) {
            return "Missing signature";
        }

        return null;
    }

    /**
     * Routes a rejection decision to the rejected queue.
     *
     * @param event the original SignedEvent
     * @param reason the reason for rejection
     * @param message descriptive message
     */
    private void routeRejected(SignedEvent event, AuditReason reason, String message) {
        router.routeRejected(event, reason, message);
    }

}



