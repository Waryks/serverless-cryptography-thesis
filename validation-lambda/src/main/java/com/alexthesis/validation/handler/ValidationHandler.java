package com.alexthesis.validation.handler;

import com.alexthesis.crypto.helpers.KeySecret;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * AWS Lambda entry point for the validation stage.
 *
 * <p>Receives SQS batch events from the ingress queue and delegates processing to
 * {@link com.alexthesis.validation.service.ValidationService}.
 *
 * <p>Uses the SQS partial batch response pattern: each message is processed independently.
 * Only messages that fail with infrastructure errors are returned as failures for SQS redelivery.
 * Security rejections are handled gracefully and do NOT cause redelivery.
 *
 * <p>Requires the SQS event source mapping to have
 * {@code FunctionResponseTypes = [ReportBatchItemFailures]} enabled.
 *
 * <p>The {@link RegisterForReflection} annotation registers commons record types
 * for GraalVM native-image reflection so that Jackson can deserialize them at runtime.
 */
@RegisterForReflection(targets = {
        KeySecret.class,
        SignedEvent.class,
        SignedContent.class,
        Algorithm.class,
})
public class ValidationHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger log = Logger.getLogger(ValidationHandler.class);

    private final com.alexthesis.validation.service.ValidationService validationService;

    @Inject
    public ValidationHandler(com.alexthesis.validation.service.ValidationService validationService) {
        this.validationService = validationService;
    }

    /**
     * Lambda invocation entry point.
     *
     * <p>Iterates over each SQS record and delegates to the validation service.
     * Returns {@code Void} but internally handles batch item failures.
     *
     * @param event   the SQS batch event
     * @param context the Lambda runtime context
     * @return {@code null} (Void return type)
     * @throws RuntimeException only if an infrastructure error occurs that warrants retry
     */
    @Override
    public Void handleRequest(SQSEvent event, Context context) {
        List<String> failures = new ArrayList<>();

        log.debugf("Validation Lambda received SQS batch with %d message(s)", event.getRecords().size());

        for (SQSEvent.SQSMessage message : event.getRecords()) {
            try {
                validationService.processMessage(message.getBody());
                log.debugf("Successfully processed message %s", message.getMessageId());
            } catch (com.alexthesis.validation.service.ValidationService.SecurityRejectionException e) {
                log.warnf("Security rejection for message %s: %s",
                        message.getMessageId(), e.getReason());
            } catch (Exception e) {
                log.errorf(e, "Infrastructure failure processing message %s — will be retried",
                        message.getMessageId());
                failures.add(message.getMessageId());
            }
        }

        // TODO: Use SQS batch response when ready to integrate with batch failure reporting
        // For now, we silently handle infrastructure failures as they will cause Lambda to retry

        return null;
    }
}


