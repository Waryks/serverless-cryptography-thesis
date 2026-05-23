package com.alexthesis.lambda;

import com.alexthesis.crypto.helpers.KeySecret;
import com.alexthesis.crypto.SecretService;
import com.alexthesis.crypto.SignatureService;
import com.alexthesis.events.EventPublisher;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.alexthesis.metrics.ColdStartTracker;
import com.alexthesis.metrics.MetricsContext;
import com.alexthesis.metrics.TimingStage;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Core business logic for the producer Lambda.
 * Orchestrates secret retrieval, signing, and SQS publishing for each incoming event.
 *
 * <p>Cold start detection is handled via a JVM-lifetime {@link AtomicBoolean} flag:
 * the first invocation within a container lifetime is marked as a cold start,
 * all subsequent ones within the same container are warm.
 */
@ApplicationScoped
public class ProducerService {

    private static final long NS_PER_MS = 1_000_000L;

    private final EventPublisher publisher;
    private final SecretService secretService;
    private final SignatureService signatureService;

    @Inject
    public ProducerService(EventPublisher publisher,
                           SecretService secretService,
                           SignatureService signatureService) {
        this.publisher = publisher;
        this.secretService = secretService;
        this.signatureService = signatureService;
    }

    /**
     * Processes an incoming {@link SignedEvent} by:
     * <ol>
     *   <li>Loading the key from Secrets Manager using {@link SignedContent#keyId()}</li>
     *   <li>Canonically serialising the content and signing it with the appropriate algorithm</li>
     *   <li>Publishing the signed event to SQS</li>
     * </ol>
     *
     * @param inputSignedEvent the event received from the benchmark client, containing
     *                         the payload, algorithm choice, and key reference
     * @return a {@link ProducerResponse} with the event ID, cold start flag, and
     *         total processing duration in milliseconds
     */
    public ProducerResponse processEvent(SignedEvent inputSignedEvent) {
        String eventId = inputSignedEvent.content().eventId();
        boolean isColdStart = ColdStartTracker.isColdStartAndMark("producer");

        MetricsContext ctx = MetricsContext.create("producer", eventId, isColdStart);
        long startTime = System.nanoTime();

        try (ctx) {
            ctx.start(TimingStage.LAMBDA_HANDLER);

            SignedContent content = inputSignedEvent.content();

            ctx.start(TimingStage.KEY_LOADING);
            KeySecret secret = secretService.getSecret(content.keyId());
            ctx.stop(TimingStage.KEY_LOADING);

            ctx.start(TimingStage.CONTENT_SERIALIZATION);
            // serialization may happen inside signature service, but we mark the logical step
            ctx.stop(TimingStage.CONTENT_SERIALIZATION);

            ctx.start(TimingStage.SIGNING);
            String signatureB64 = signatureService.sign(content, secret);
            ctx.stop(TimingStage.SIGNING);

            ctx.start(TimingStage.SQS_PUBLISH);
            publisher.publish(new SignedEvent(content, signatureB64));
            ctx.stop(TimingStage.SQS_PUBLISH);

            ctx.stop(TimingStage.LAMBDA_HANDLER);

            long endTime = System.nanoTime();
            double durationMs = (endTime - startTime) / (double) NS_PER_MS;

            // Emit timing snapshot to logs so benchmark runner can collect timings from logs.
            ctx.snapshot().ifPresent(s -> {
                // log a single-line JSON representation
                // use logger from this class if needed
                System.out.println(s.toJson());
            });

            return new ProducerResponse(content.eventId(), isColdStart, durationMs);
        }
    }

    // ... existing helper methods removed; signing is performed inline to allow timing.
}

