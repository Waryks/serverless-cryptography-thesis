package com.alexthesis.persistence.handler;

import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.alexthesis.persistence.service.PersistenceService;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

@RegisterForReflection(targets = {
        SignedEvent.class,
        SignedContent.class,
        Algorithm.class,
})
public class PersistenceHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger log = Logger.getLogger(PersistenceHandler.class);

    private final PersistenceService persistenceService;

    @Inject
    public PersistenceHandler(PersistenceService persistenceService) {
        this.persistenceService = persistenceService;
    }

    @Override
    public Void handleRequest(SQSEvent event, Context context) {
        log.debugf("Persistence Lambda received SQS batch with %d message(s)", event.getRecords().size());

        for (SQSEvent.SQSMessage message : event.getRecords()) {
            persistenceService.processMessage(message.getBody());
            log.debugf("Successfully processed message %s", message.getMessageId());
        }

        return null;
    }
}

