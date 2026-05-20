package com.alexthesis.audit.repository;

import com.alexthesis.audit.model.AuditRecord;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

import java.util.HashMap;
import java.util.Map;

@ApplicationScoped
public class AuditRepository {

    private static final Logger log = Logger.getLogger(AuditRepository.class);

    private final DynamoDbClient dynamoDbClient;
    private final String table;

    protected AuditRepository() {
        this.dynamoDbClient = null;
        this.table = null;
    }

    @Inject
    public AuditRepository(DynamoDbClient dynamoDbClient,
                           @ConfigProperty(name = "thesis.dynamodb.audit-table") String table) {
        this.dynamoDbClient = dynamoDbClient;
        this.table = table;
    }

    public void save(AuditRecord record) {
        dynamoDbClient.putItem(PutItemRequest.builder()
                .tableName(table)
                .item(buildItem(record))
                .build());

        log.infof("eventId=%s auditPersisted=true reason=%s", record.eventId(), record.reason());
    }

    private Map<String, AttributeValue> buildItem(AuditRecord record) {
        Map<String, AttributeValue> item = new HashMap<>();

        if (record.auditId() != null) item.put("auditId", AttributeValue.fromS(record.auditId()));
        if (record.eventId() != null) item.put("eventId", AttributeValue.fromS(record.eventId()));
        if (record.reason() != null) item.put("reason", AttributeValue.fromS(record.reason()));
        if (record.message() != null) item.put("message", AttributeValue.fromS(record.message()));
        if (record.algorithm() != null) item.put("algorithm", AttributeValue.fromS(record.algorithm()));
        if (record.keyId() != null) item.put("keyId", AttributeValue.fromS(record.keyId()));
        if (record.payload() != null) item.put("payload", AttributeValue.fromS(record.payload()));
        if (record.signatureB64() != null) item.put("signatureB64", AttributeValue.fromS(record.signatureB64()));

        item.put("rejectedAtEpochMs", AttributeValue.fromN(String.valueOf(record.rejectedAtEpochMs())));
        item.put("persistedAtEpochMs", AttributeValue.fromN(String.valueOf(record.persistedAtEpochMs())));

        return item;
    }
}

