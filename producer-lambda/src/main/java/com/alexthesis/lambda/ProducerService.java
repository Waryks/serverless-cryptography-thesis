package com.alexthesis.lambda;

import com.alexthesis.crypto.helpers.KeySecret;
import com.alexthesis.crypto.SecretService;
import com.alexthesis.crypto.SignatureService;
import com.alexthesis.events.EventPublisher;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
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

    private static final AtomicBoolean COLDSTART_FLAG = new AtomicBoolean(true);
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
        boolean isColdStart = COLDSTART_FLAG.getAndSet(false);
        long startTime = System.nanoTime();

        SignedContent content = inputSignedEvent.content();
        String signatureB64 = handleSigningContent(content);

        publisher.publish(new SignedEvent(content, signatureB64));

        long endTime = System.nanoTime();
        double durationMs = (endTime - startTime) / (double) NS_PER_MS;

        return new ProducerResponse(content.eventId(), isColdStart, durationMs);
    }

    private String handleSigningContent(SignedContent content) {
        KeySecret secret = secretService.getSecret(content.keyId());

        return signatureService.sign(content, secret);
    }
}

