package com.alexthesis.persistence.repository;

import com.alexthesis.persistence.model.LedgerRecord;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

import java.util.Map;

@ApplicationScoped
public class LedgerRepository {

    private static final Logger log = Logger.getLogger(LedgerRepository.class);

    private final DynamoDbClient dynamoDbClient;
    private final String table;

    protected LedgerRepository() {
        this.dynamoDbClient = null;
        this.table = null;
    }

    @Inject
    public LedgerRepository(DynamoDbClient dynamoDbClient,
                            @ConfigProperty(name = "thesis.dynamodb.ledger-table") String table) {
        this.dynamoDbClient = dynamoDbClient;
        this.table = table;
    }

    public void save(LedgerRecord record) {
        dynamoDbClient.putItem(PutItemRequest.builder()
                .tableName(table)
                .item(buildItem(record))
                .build());
        log.infof("eventId=%s persisted=true", record.eventId());
    }

    private Map<String, AttributeValue> buildItem(LedgerRecord record) {
        return Map.of(
                "eventId", AttributeValue.fromS(record.eventId()),
                "algorithm", AttributeValue.fromS(record.algorithm()),
                "keyId", AttributeValue.fromS(record.keyId()),
                "payload", AttributeValue.fromS(record.payload()),
                "signatureB64", AttributeValue.fromS(record.signatureB64()),
                "acceptedAtEpochMs", AttributeValue.fromN(String.valueOf(record.acceptedAtEpochMs())),
                "persistedAtEpochMs", AttributeValue.fromN(String.valueOf(record.persistedAtEpochMs()))
        );
    }
}

