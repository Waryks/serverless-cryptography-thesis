package com.alexthesis.dynamo;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

import java.util.Map;

/**
 * Base repository providing common DynamoDB write primitives for the consumer pipeline.
 * Concrete subclasses supply the target table name and build the item attribute map.
 */
public abstract class DynamoRepository {

    protected final DynamoDbClient dynamoDbClient;

    protected DynamoRepository(DynamoDbClient dynamoDbClient) {
        this.dynamoDbClient = dynamoDbClient;
    }

    /**
     * Persists {@code item} to the table returned by {@link #tableName()}.
     *
     * @param item attribute map to write
     */
    protected void putItem(Map<String, AttributeValue> item) {
        dynamoDbClient.putItem(PutItemRequest.builder()
                .tableName(tableName())
                .item(item)
                .build());
    }

    /**
     * Returns the DynamoDB table name this repository writes to.
     */
    protected abstract String tableName();
}

