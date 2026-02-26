package com.alexthesis.lambda;

import com.alexthesis.crypto.KeySecret;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * AWS Lambda entry-point for the consumer pipeline.
 *
 * <p>Uses SQS partial batch response: each message in the batch is processed
 * independently. Only messages that fail processing are returned as
 * {@link SQSBatchResponse.BatchItemFailure}, so SQS redelivers only those —
 * not the entire batch. This prevents a single bad message (e.g. a tampered
 * payload that correctly triggers {@code InvalidSignatureException}) from
 * blocking all other messages in the same batch.
 *
 * <p>Requires the SQS event source mapping to have
 * {@code FunctionResponseTypes = [ReportBatchItemFailures]} enabled.
 * This is configured in {@code run_benchmark.py} when the trigger is created.
 *
 * <p>The {@link RegisterForReflection} annotation registers commons record types
 * for GraalVM native-image reflection so that Jackson can deserialise them at runtime.
 */
@RegisterForReflection(targets = {
        KeySecret.class,
        SignedEvent.class,
        SignedContent.class,
        Algorithm.class,
})
public class ConsumerHandler implements RequestHandler<SQSEvent, SQSBatchResponse> {

    private static final Logger log = Logger.getLogger(ConsumerHandler.class);

    private final ConsumerService consumerService;

    @Inject
    public ConsumerHandler(ConsumerService consumerService) {
        this.consumerService = consumerService;
    }

    @Override
    public SQSBatchResponse handleRequest(SQSEvent event, Context context) {
        List<SQSBatchResponse.BatchItemFailure> failures = new ArrayList<>();

        for (SQSEvent.SQSMessage message : event.getRecords()) {
            try {
                consumerService.processMessage(message.getBody());
            } catch (ConsumerService.SecurityRejectionException e) {
                log.warnf("Discarding message %s: security rejection — %s [%s]",
                        message.getMessageId(), e.getMessage(), e.getClass().getSimpleName());
            } catch (Exception e) {
                log.errorf(e, "Transient failure processing message %s — will retry",
                        message.getMessageId());
                failures.add(SQSBatchResponse.BatchItemFailure.builder()
                        .withItemIdentifier(message.getMessageId())
                        .build());
            }
        }

        return SQSBatchResponse.builder()
                .withBatchItemFailures(failures)
                .build();
    }
}
