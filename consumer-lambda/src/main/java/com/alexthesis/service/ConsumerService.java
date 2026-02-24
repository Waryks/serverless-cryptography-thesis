package com.alexthesis.service;

import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

@ApplicationScoped
public class ConsumerService {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Logger LOGGER = Logger.getLogger(ConsumerService.class);

    private final boolean replayCheckEnabled;
    private final long replayWindowMs;

    public ConsumerService(@ConfigProperty(name = "thesis.replay-check.enabled", defaultValue = "true") boolean replayCheckEnabled,
                           @ConfigProperty(name = "thesis.replay-check.window-ms", defaultValue = "300000") long replayWindowMs) {
        this.replayCheckEnabled = replayCheckEnabled;
        this.replayWindowMs = replayWindowMs;
    }

    public void processMessage(String messageBodyJson) {
        try {
            SignedEvent event = MAPPER.readValue(messageBodyJson, SignedEvent.class);
            SignedContent content = event.content();

            // TODO:
            // 1. Recreate canonical bytes of event.content()
            // 2. Load key using event.content().keyId()
            // 3. Verify signature using event.content().algorithm()
            // 4. Reject if invalid

            if (!isValidSignature(event)) {
                throw new InvalidSignatureException("Invalid signature");
            }

            processWindow(content);

            // TODO:
            // 5. Write to DynamoDB (ledger + dedup table)

            LOGGER.info("Processed message with eventId: " + event.content().eventId()
                    + " algorithm: " + event.content().algorithm());

        } catch (Exception e) {
            throw new RuntimeException("Failed to process SQS message", e);
        }
    }

    private boolean isValidSignature(SignedEvent event) {
        //TODO: Implement actual signature verification logic
        return true;
    }

    private void processWindow(SignedContent content) {
        if(!replayCheckEnabled) {
            return;
        }

        long now = System.currentTimeMillis();
        long age = now - content.timestampEpochMs();

        if (age > replayWindowMs) {
            throw new InvalidSignatureException("Replay window exceeded. Event age: " + age + "ms");
        }
    }

    private static class InvalidSignatureException extends RuntimeException {
        public InvalidSignatureException(String message) {
            super(message);
        }
    }
}
