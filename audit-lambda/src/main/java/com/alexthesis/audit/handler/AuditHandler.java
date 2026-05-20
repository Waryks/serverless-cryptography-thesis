package com.alexthesis.audit.handler;

import com.alexthesis.audit.service.AuditService;
import com.alexthesis.messaging.RejectedEvent;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.alexthesis.messaging.AuditReason;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

@RegisterForReflection(targets = {
        RejectedEvent.class,
        SignedEvent.class,
        SignedContent.class,
        AuditReason.class
})
public class AuditHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger log = Logger.getLogger(AuditHandler.class);

    private final AuditService auditService;

    @Inject
    public AuditHandler(AuditService auditService) {
        this.auditService = auditService;
    }

    @Override
    public Void handleRequest(SQSEvent event, Context context) {
        log.debugf("Audit Lambda received SQS batch with %d message(s)", event.getRecords().size());

        for (SQSEvent.SQSMessage message : event.getRecords()) {
            auditService.processMessage(message.getBody());
            log.debugf("Successfully processed message %s", message.getMessageId());
        }

        return null;
    }
}

