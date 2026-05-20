package com.alexthesis.validation.handler;

import com.alexthesis.crypto.helpers.KeySecret;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.AuditReason;
import com.alexthesis.messaging.RejectedEvent;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

/**
 * AWS Lambda entry point for the validation stage.
 *
 * <p>Receives SQS batch events from the ingress queue and delegates processing to
 * {@link com.alexthesis.validation.service.ValidationService}.
 *
 * <p>Security rejections are handled inside the service and do NOT throw.
 * Infrastructure failures are allowed to escape so SQS can retry the batch.
 *
 * <p>The {@link RegisterForReflection} annotation registers commons record types
 * for GraalVM native-image reflection so that Jackson can deserialize them at runtime.
 */
@RegisterForReflection(targets = {
        KeySecret.class,
        SignedEvent.class,
        SignedContent.class,
        Algorithm.class,
        RejectedEvent.class,
        AuditReason.class,
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
     * Security rejections are handled by the service; infrastructure failures are
     * rethrown so the Lambda invocation fails and SQS retries the batch.
     *
     * @param event   the SQS batch event
     * @param context the Lambda runtime context
     * @return {@code null} (Void return type)
     * @throws RuntimeException only if an infrastructure error occurs that warrants retry
     */
    @Override
    public Void handleRequest(SQSEvent event, Context context) {
        log.debugf("Validation Lambda received SQS batch with %d message(s)", event.getRecords().size());

        for (SQSEvent.SQSMessage message : event.getRecords()) {
            validationService.processMessage(message.getBody());
            log.debugf("Successfully processed message %s", message.getMessageId());
        }

        return null;
    }
}


