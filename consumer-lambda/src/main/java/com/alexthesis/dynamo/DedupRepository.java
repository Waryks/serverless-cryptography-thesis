package com.alexthesis.dynamo;

import com.alexthesis.messaging.SignedContent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;

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
     * Used for standalone dedup writes (e.g. in tests).
     * For production use, prefer {@link #buildTransactItem(SignedContent)} combined
     * with a {@code TransactWriteItems} call from {@code ConsumerService}.
     *
     * @param content the signed event content whose {@code eventId} must be unique
     * @throws RuntimeException wrapping {@link ConditionalCheckFailedException} if a duplicate is detected
     */
    public void checkAndInsert(SignedContent content) {
        long ttlEpochSeconds = (System.currentTimeMillis() / 1000L) + dedupTtlSeconds;
        Map<String, AttributeValue> item = Map.of(
                "eventId", AttributeValue.fromS(content.eventId()),
                "ttl",     AttributeValue.fromN(String.valueOf(ttlEpochSeconds))
        );

        insertDedupRecord(item, content.eventId());
    }

    /**
     * Builds a {@link TransactWriteItem} for use inside a {@code TransactWriteItems} request.
     * The {@code attribute_not_exists(eventId)} condition is included so a replay will cause
     * the entire transaction to fail atomically.
     *
     * @param content the event whose dedup entry should be written
     * @return a transact-write item ready to be combined with other items in the same transaction
     */
    public TransactWriteItem buildTransactItem(SignedContent content) {
        long ttlEpochSeconds = (System.currentTimeMillis() / 1000L) + dedupTtlSeconds;
        Map<String, AttributeValue> item = Map.of(
                "eventId", AttributeValue.fromS(content.eventId()),
                "ttl",     AttributeValue.fromN(String.valueOf(ttlEpochSeconds))
        );

        return TransactWriteItem.builder()
                .put(Put.builder()
                        .tableName(table)
                        .item(item)
                        .conditionExpression("attribute_not_exists(eventId)")
                        .build())
                .build();
    }

    private void insertDedupRecord(Map<String, AttributeValue> item, String eventId) {
        try {
            dynamoDbClient.putItem(builder -> builder
                    .tableName(table)
                    .item(item)
                    .conditionExpression("attribute_not_exists(eventId)")
            );
            log.debugf("Dedup record inserted for eventId: %s", eventId);
        } catch (ConditionalCheckFailedException e) {
            throw new RuntimeException("Duplicate eventId detected: " + eventId, e);
        }
    }

    @Override
    protected String tableName() {
        return table;
    }
}
