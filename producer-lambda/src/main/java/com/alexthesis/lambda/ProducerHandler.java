package com.alexthesis.lambda;

import com.alexthesis.crypto.helpers.KeySecret;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.inject.Inject;

/**
 * AWS Lambda entry point for the producer.
 * Delegates all business logic to {@link ProducerService}, keeping the handler
 * thin and focused solely on satisfying the Lambda {@link RequestHandler} contract.
 *
 * <p>The {@link RegisterForReflection} annotation registers commons record types
 * and {@link ProducerResponse} for GraalVM native-image reflection so that Jackson
 * can deserialise/serialise them at runtime.
 */
@RegisterForReflection(targets = {
        KeySecret.class,
        SignedEvent.class,
        SignedContent.class,
        Algorithm.class,
        ProducerResponse.class,
})
public class ProducerHandler implements RequestHandler<SignedEvent, ProducerResponse> {

    private final ProducerService producerService;

    @Inject
    public ProducerHandler(ProducerService producerService) {
        this.producerService = producerService;
    }

    /**
     * Lambda invocation entry point.
     *
     * @param signedEvent the event sent by the benchmark client
     * @param context     the Lambda runtime context (unused — timing is measured internally)
     * @return a {@link ProducerResponse} containing the event ID, cold start flag,
     *         and end-to-end processing duration
     */
    @Override
    public ProducerResponse handleRequest(SignedEvent signedEvent, Context context) {
        return producerService.processEvent(signedEvent);
    }
}

