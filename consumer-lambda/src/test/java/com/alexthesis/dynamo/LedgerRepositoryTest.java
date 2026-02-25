package com.alexthesis.dynamo;

import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link LedgerRepository}.
 * The {@link DynamoDbClient} is mocked — no AWS calls are made.
 */
@ExtendWith(MockitoExtension.class)
class LedgerRepositoryTest {

    private static final String TABLE = "thesis-ledger";

    @Mock
    DynamoDbClient dynamoDbClient;

    LedgerRepository ledgerRepository;

    @BeforeEach
    void setUp() {
        ledgerRepository = new LedgerRepository(dynamoDbClient, TABLE);
    }

    @Test
    void save_invokesputItemOnce() {
        ledgerRepository.save(buildContent("evt-1"));

        verify(dynamoDbClient, times(1)).putItem(any(PutItemRequest.class));
    }

    @Test
    void save_writesToCorrectTable() {
        ledgerRepository.save(buildContent("evt-1"));

        ArgumentCaptor<PutItemRequest> captor = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(captor.capture());

        assertThat(captor.getValue().tableName()).isEqualTo(TABLE);
    }

    @Test
    void save_itemContainsAllExpectedAttributes() {
        long before = System.currentTimeMillis();
        SignedContent content = buildContent("evt-2");

        ledgerRepository.save(content);

        ArgumentCaptor<PutItemRequest> captor = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(captor.capture());

        Map<String, AttributeValue> item = captor.getValue().item();

        assertThat(item.get("eventId").s()).isEqualTo("evt-2");
        assertThat(item.get("algorithm").s()).isEqualTo(Algorithm.HMAC_SHA256.name());
        assertThat(item.get("keyId").s()).isEqualTo("test-key");
        assertThat(Long.parseLong(item.get("timestampEpochMs").n())).isEqualTo(content.timestampEpochMs());
        assertThat(Long.parseLong(item.get("processedAtMs").n())).isGreaterThanOrEqualTo(before);
    }

    @Test
    void save_tableName_returnsConfiguredTable() {
        assertThat(ledgerRepository.tableName()).isEqualTo(TABLE);
    }

    @Test
    void save_dynamoDbThrows_propagatesException() {
        when(dynamoDbClient.putItem(any(PutItemRequest.class)))
                .thenThrow(new RuntimeException("DynamoDB unavailable"));

        assertThatThrownBy(() -> ledgerRepository.save(buildContent("evt-err")))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("DynamoDB unavailable");
    }

    private static SignedContent buildContent(String eventId) {
        return new SignedContent(
                eventId,
                System.currentTimeMillis(),
                Algorithm.HMAC_SHA256,
                "test-key",
                JsonNodeFactory.instance.objectNode().put("data", "value")
        );
    }
}


