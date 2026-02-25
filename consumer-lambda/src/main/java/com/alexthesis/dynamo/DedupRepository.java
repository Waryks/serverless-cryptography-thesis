package com.alexthesis.dynamo;

import com.alexthesis.messaging.SignedContent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;

import java.util.Map;

/**
 * Repository responsible for deduplication of events via DynamoDB.
 *
 * <p>Uses a conditional {@code PutItem} with {@code attribute_not_exists(eventId)} to guarantee
 * that each {@code eventId} is only written once. If the item already exists the condition fails,
 * which indicates a replay attempt.
 *
 * <p>Table schema:
 * <ul>
 *   <li>Partition key: {@code eventId} (S)</li>
 *   <li>{@code ttl}  (N) — epoch-seconds TTL attribute (optional, enables DynamoDB TTL cleanup)</li>
 * </ul>
 */
@ApplicationScoped
public class DedupRepository extends DynamoRepository {

    private static final Logger log = Logger.getLogger(DedupRepository.class);

    private final String table;
    private final long dedupTtlSeconds;

    // Required by Quarkus CDI for proxying normal-scoped beans
    protected DedupRepository() {
        super(null);
        this.table = null;
        this.dedupTtlSeconds = 0;
    }

    @Inject
    public DedupRepository(DynamoDbClient dynamoDbClient,
                           @ConfigProperty(name = "thesis.dynamodb.dedup-table") String table,
                           @ConfigProperty(name = "thesis.dynamodb.dedup-ttl-seconds", defaultValue = "86400") long dedupTtlSeconds) {
        super(dynamoDbClient);
        this.table = table;
        this.dedupTtlSeconds = dedupTtlSeconds;
    }

    /**
     * Attempts to insert a deduplication record for the given event.
     *
     * @param content the signed event content whose {@code eventId} must be unique
     * @throws DuplicateEventException if a record with the same {@code eventId} already exists
     */
    public void checkAndInsert(SignedContent content) {
        long ttlEpochSeconds = (System.currentTimeMillis() / 1000L) + dedupTtlSeconds;

        Map<String, AttributeValue> item = Map.of(
                "eventId", AttributeValue.fromS(content.eventId()),
                "ttl",     AttributeValue.fromN(String.valueOf(ttlEpochSeconds))
        );

        try {
            dynamoDbClient.putItem(builder -> builder
                    .tableName(table)
                    .item(item)
                    .conditionExpression("attribute_not_exists(eventId)")
            );
            log.debugf("Dedup record inserted for eventId: %s", content.eventId());
        } catch (ConditionalCheckFailedException e) {
            throw new DuplicateEventException("Duplicate eventId detected: " + content.eventId(), e);
        }
    }

    @Override
    protected String tableName() {
        return table;
    }

    /** Thrown when an event with the same {@code eventId} has already been processed. */
    public static class DuplicateEventException extends RuntimeException {
        public DuplicateEventException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

