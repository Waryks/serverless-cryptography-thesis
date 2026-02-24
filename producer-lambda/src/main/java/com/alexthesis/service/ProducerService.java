package com.alexthesis.service;

import com.alexthesis.events.EventPublisher;
import com.alexthesis.lambda.ProducerResponse;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.concurrent.atomic.AtomicBoolean;

@ApplicationScoped
public class ProducerService {

    private static final AtomicBoolean COLDSTART_FLAG = new AtomicBoolean(true);
    private static final Integer NS_CONVERTER = 1_000_000;

    private final EventPublisher publisher;

    @Inject
    public ProducerService(EventPublisher publisher) {
        this.publisher = publisher;
    }

    public ProducerResponse processEvent(SignedEvent inputSignedEvent) {
        boolean isColdStart = COLDSTART_FLAG.getAndSet(false);
        long startTime = System.nanoTime();

        SignedContent content = inputSignedEvent.content();
        String signature = handleSignature(content);

        // TODO:
        // 1. Load key using content.keyId()
        // 2. Serialize content deterministaclly
        // 3. Sign bytes based on content.algorithm()
        // 4. Base64 encode signature

        publisher.publish(new SignedEvent(content, signature));

        long endTime = System.nanoTime();
        long durationMs = (endTime - startTime) / NS_CONVERTER;

        return new ProducerResponse(content.eventId(), isColdStart, durationMs);
    }

    private String handleSignature(SignedContent content) {
        // TODO: Implement actual signature handling logic
        return "dummy-signature";
    }
}
