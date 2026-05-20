package com.alexthesis.validation.checks;

import com.alexthesis.messaging.SignedContent;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

/**
 * DynamoDB-backed deduplication store for validation events.
 *
 * <p>Each processed event is written to {@code thesis_dedup} with a conditional put on
 * {@code eventId}. If the item already exists, the put fails with
 * {@link ConditionalCheckFailedException} and the event is treated as a duplicate.
 *
 * <p>Replay protection and deduplication are controlled independently by policy.
 * Deduplication is skipped entirely when {@code thesis.security.dedup-enabled=false}.
 */
@ApplicationScoped
public class DedupStore {

    private static final Logger log = Logger.getLogger(DedupStore.class);

    private final DynamoDbClient dynamoDbClient;
    private final String tableName;
    private final boolean enabled;
    private final long dedupTtlSeconds;

    public DedupStore(
            DynamoDbClient dynamoDbClient,
            @ConfigProperty(name = "thesis.dynamodb.dedup-table") String tableName,
            @ConfigProperty(name = "thesis.security.dedup-enabled", defaultValue = "true") boolean enabled,
            @ConfigProperty(name = "thesis.dynamodb.dedup-ttl-seconds", defaultValue = "86400") long dedupTtlSeconds) {
        this.dynamoDbClient = dynamoDbClient;
        this.tableName = tableName;
        this.enabled = enabled;
        this.dedupTtlSeconds = dedupTtlSeconds;
    }

    /**
     * Returns {@code true} when the eventId has not been seen before.
     *
     * <p>If deduplication is disabled the method returns {@code true} without touching DynamoDB.
     * Duplicate events return {@code false}. Infrastructure failures are not swallowed.
     */
    public boolean isNewEvent(SignedContent content) {
        if (!enabled) {
            return true;
        }

        ProcessedEventRecord record = ProcessedEventRecord.from(content, dedupTtlSeconds);
        PutItemRequest request = PutItemRequest.builder()
                .tableName(tableName)
                .item(record.toItem())
                .conditionExpression("attribute_not_exists(eventId)")
                .build();

        try {
            dynamoDbClient.putItem(request);
            log.debugf("Dedup record stored for eventId=%s", content.eventId());
            return true;
        } catch (ConditionalCheckFailedException e) {
            log.infof("Duplicate eventId rejected by dedup store: %s", content.eventId());
            return false;
        }
    }
}


