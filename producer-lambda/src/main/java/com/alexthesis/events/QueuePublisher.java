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
 * The queue name is bound from {@code thesis.sqs.queue-name} in {@code application.properties}.
 */
@ApplicationScoped
public class QueuePublisher implements EventPublisher {

    private static final Logger log = Logger.getLogger(QueuePublisher.class);

    private final SqsClient sqsClient;
    private final ObjectMapper objectMapper;
    private final String queueName;
    private volatile String queueUrl;

    public QueuePublisher(SqsClient sqsClient, ObjectMapper objectMapper,
                          @ConfigProperty(name = "thesis.sqs.queue-name") String queueName) {
        this.sqsClient = sqsClient;
        this.objectMapper = objectMapper;
        this.queueName = queueName;
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
            String resolvedQueueUrl = resolveQueueUrl();

            var response = sqsClient.sendMessage(m -> m
                    .queueUrl(resolvedQueueUrl)
                    .messageBody(message));

            log.infof("Published eventId=%s messageId=%s",
                    event.content().eventId(), response.messageId());
            log.debugf("Full message body: %s", message);
        } catch (Exception e) {
            throw new RuntimeException("Failed to publish event to SQS", e);
        }
    }

    private String resolveQueueUrl() {
        String cached = queueUrl;
        if (cached != null) {
            return cached;
        }
        synchronized (this) {
            if (queueUrl == null) {
                queueUrl = sqsClient.getQueueUrl(r -> r.queueName(queueName)).queueUrl();
                log.debugf("Resolved queue '%s' to URL '%s'", queueName, queueUrl);
            }
            return queueUrl;
        }
    }
}
