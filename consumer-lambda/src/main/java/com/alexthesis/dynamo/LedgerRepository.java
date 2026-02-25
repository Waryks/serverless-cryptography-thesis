package com.alexthesis.dynamo;

import com.alexthesis.messaging.SignedContent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;

import java.util.Map;

/**
 * Repository responsible for persisting verified events to the DynamoDB ledger table.
 *
 * <p>Each successfully verified event is recorded with its full metadata so the ledger
 * provides an auditable, append-only history of processed events.
 *
 * <p>Table schema:
 * <ul>
 *   <li>Partition key: {@code eventId} (S)</li>
 *   <li>{@code timestampEpochMs} (N)</li>
 *   <li>{@code algorithm}        (S)</li>
 *   <li>{@code keyId}            (S)</li>
 *   <li>{@code processedAtMs}    (N) — wall-clock time when the consumer persisted the record</li>
 * </ul>
 */
@ApplicationScoped
public class LedgerRepository extends DynamoRepository {

    private static final Logger log = Logger.getLogger(LedgerRepository.class);

    private final String table;

    // Required by Quarkus CDI for proxying normal-scoped beans
    protected LedgerRepository() {
        super(null);
        this.table = null;
    }

    @Inject
    public LedgerRepository(DynamoDbClient dynamoDbClient,
                            @ConfigProperty(name = "thesis.dynamodb.ledger-table") String table) {
        super(dynamoDbClient);
        this.table = table;
    }

    /**
     * Writes a ledger entry for the supplied {@code content}.
     * Used for standalone ledger writes (e.g. in tests).
     *
     * @param content the verified event content to record
     */
    public void save(SignedContent content) {
        putItem(buildItem(content));
        log.debugf("Ledger entry saved for eventId: %s", content.eventId());
    }

    /**
     * Builds a {@link TransactWriteItem} for use inside a {@code TransactWriteItems} request.
     *
     * @param content the verified event content to record
     * @return a transact-write item ready to be combined with other items in the same transaction
     */
    public TransactWriteItem buildTransactItem(SignedContent content) {
        return TransactWriteItem.builder()
                .put(Put.builder()
                        .tableName(table)
                        .item(buildItem(content))
                        .build())
                .build();
    }

    private Map<String, AttributeValue> buildItem(SignedContent content) {
        return Map.of(
                "eventId",          AttributeValue.fromS(content.eventId()),
                "timestampEpochMs", AttributeValue.fromN(String.valueOf(content.timestampEpochMs())),
                "algorithm",        AttributeValue.fromS(content.algorithm().name()),
                "keyId",            AttributeValue.fromS(content.keyId()),
                "processedAtMs",    AttributeValue.fromN(String.valueOf(System.currentTimeMillis()))
        );
    }

    @Override
    protected String tableName() {
        return table;
    }
}
