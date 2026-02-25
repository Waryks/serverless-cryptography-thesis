package com.alexthesis.events;

import com.alexthesis.messaging.SignedEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.sqs.SqsClient;

/**
 * SQS-backed implementation of {@link EventPublisher}.
 * Serialises a {@link SignedEvent} to JSON and sends it to the configured SQS queue.
 * The queue URL is bound from {@code thesis.sqs.queue-name} in {@code application.properties}.
 */
@ApplicationScoped
public class QueuePublisher implements EventPublisher {

    private static final Logger log = Logger.getLogger(QueuePublisher.class);

    private final SqsClient sqsClient;
    private final ObjectMapper objectMapper;
    private final String queueUrl;

    public QueuePublisher(SqsClient sqsClient, ObjectMapper objectMapper,
                          @ConfigProperty(name = "thesis.sqs.queue-name") String queueUrl) {
        this.sqsClient = sqsClient;
        this.objectMapper = objectMapper;
        this.queueUrl = queueUrl;
    }

    /**
     * Serialises {@code event} to JSON and sends it as a single SQS message.
     *
     * @param event the fully signed event to publish
     * @throws RuntimeException if serialisation or the SQS send call fails
     */
    @Override
    public void publish(SignedEvent event) {
        try {
            String message = objectMapper.writeValueAsString(event);

            sqsClient.sendMessage(m -> m
                    .queueUrl(queueUrl)
                    .messageBody(message));

            log.info("Sent message to queue: " + message);
        } catch (Exception e) {
            throw new RuntimeException("Failed to publish event to SQS", e);
        }
    }
}
