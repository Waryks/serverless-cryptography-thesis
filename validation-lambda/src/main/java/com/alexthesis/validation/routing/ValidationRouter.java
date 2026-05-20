package com.alexthesis.validation.routing;

import com.alexthesis.messaging.RejectedEvent;
import com.alexthesis.messaging.SignedEvent;
import com.alexthesis.messaging.AuditReason;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.GetQueueUrlRequest;
import software.amazon.awssdk.services.sqs.model.GetQueueUrlResponse;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Routes validation decisions to the appropriate SQS queues.
 *
 * <p>Accepted events are published to {@code thesis-accepted-events}.
 * Rejected events are published to {@code thesis-rejected-events}.
 *
 * <p>Queue URLs are resolved once from queue names and cached for efficiency.
 */
@ApplicationScoped
public class ValidationRouter {

    private static final Logger log = Logger.getLogger(ValidationRouter.class);

    private final SqsClient sqsClient;
    private final ObjectMapper objectMapper;
    private final String acceptedQueueName;
    private final String rejectedQueueName;
    private final Map<String, String> queueUrlCache = new ConcurrentHashMap<>();

    @Inject
    public ValidationRouter(
            SqsClient sqsClient,
            ObjectMapper objectMapper,
            @ConfigProperty(name = "thesis.sqs.accepted-queue-name") String acceptedQueueName,
            @ConfigProperty(name = "thesis.sqs.rejected-queue-name") String rejectedQueueName) {
        this.sqsClient = sqsClient;
        this.objectMapper = objectMapper;
        this.acceptedQueueName = acceptedQueueName;
        this.rejectedQueueName = rejectedQueueName;
    }

    /**
     * Routes an accepted event to the accepted queue.
     *
     * @param event the SignedEvent that passed validation
     * @throws RuntimeException if SQS publishing fails
     */
    public void routeAccepted(SignedEvent event) {
        String queueUrl = resolveQueueUrl(acceptedQueueName);
        String messageBody = serializeEvent(event);

        SendMessageRequest request = SendMessageRequest.builder()
                .queueUrl(queueUrl)
                .messageBody(messageBody)
                .build();

        sqsClient.sendMessage(request);
        log.infof("Routed accepted event %s to %s", event.content().eventId(), acceptedQueueName);
    }

    /**
     * Routes a rejected event to the rejected queue.
     *
     * @param originalEvent the original SignedEvent (may be null if deserialization failed)
     * @param reason the reason for rejection
     * @param message descriptive message about the rejection
     * @throws RuntimeException if SQS publishing fails
     */
    public void routeRejected(SignedEvent originalEvent, AuditReason reason, String message) {
        String queueUrl = resolveQueueUrl(rejectedQueueName);

        RejectedEvent rejectedEvent = new RejectedEvent(
                originalEvent,
                reason,
                message,
                System.currentTimeMillis()
        );

        String messageBody = serializeEvent(rejectedEvent);

        SendMessageRequest request = SendMessageRequest.builder()
                .queueUrl(queueUrl)
                .messageBody(messageBody)
                .build();

        sqsClient.sendMessage(request);

        String eventId = originalEvent != null ? originalEvent.content().eventId() : "unknown";
        log.infof("Routed rejected event %s (reason=%s) to %s", eventId, reason, rejectedQueueName);
    }

    /**
     * Resolves a queue name to its URL, caching the result for subsequent calls.
     *
     * @param queueName the name of the queue
     * @return the full URL for the queue
     * @throws RuntimeException if queue resolution fails
     */
    private String resolveQueueUrl(String queueName) {
        return queueUrlCache.computeIfAbsent(queueName, name -> {
            GetQueueUrlResponse response = sqsClient.getQueueUrl(
                    GetQueueUrlRequest.builder()
                            .queueName(name)
                            .build()
            );
            return response.queueUrl();
        });
    }

    private String serializeEvent(Object event) {
        try {
            return objectMapper.writeValueAsString(event);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize event for routing", e);
        }
    }
}


