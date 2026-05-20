package com.alexthesis.persistence.repository;

import com.alexthesis.persistence.model.LedgerRecord;
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

@ExtendWith(MockitoExtension.class)
class LedgerRepositoryTest {

    private static final String TABLE = "thesis_ledger";

    @Mock
    DynamoDbClient dynamoDbClient;

    LedgerRepository repository;

    @BeforeEach
    void setUp() {
        repository = new LedgerRepository(dynamoDbClient, TABLE);
    }

    @Test
    void save_writesRecordToConfiguredTable() {
        repository.save(buildRecord());

        ArgumentCaptor<PutItemRequest> captor = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(captor.capture());

        assertThat(captor.getValue().tableName()).isEqualTo(TABLE);
        Map<String, AttributeValue> item = captor.getValue().item();
        assertThat(item.get("eventId").s()).isEqualTo("evt-1");
        assertThat(item.get("algorithm").s()).isEqualTo("HMAC_SHA256");
        assertThat(item.get("keyId").s()).isEqualTo("key-1");
        assertThat(item.get("payload").s()).isEqualTo("{\"amount\":100}");
        assertThat(item.get("signatureB64").s()).isEqualTo("sig-1");
        assertThat(Long.parseLong(item.get("acceptedAtEpochMs").n())).isEqualTo(1_700_000_000_000L);
        assertThat(Long.parseLong(item.get("persistedAtEpochMs").n())).isEqualTo(1_700_000_000_123L);
    }

    @Test
    void save_dynamoDbThrows_propagatesException() {
        when(dynamoDbClient.putItem(any(PutItemRequest.class))).thenThrow(new RuntimeException("DynamoDB unavailable"));

        assertThatThrownBy(() -> repository.save(buildRecord()))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("DynamoDB unavailable");
    }

    private static LedgerRecord buildRecord() {
        return new LedgerRecord(
                "evt-1",
                "HMAC_SHA256",
                "key-1",
                "{\"amount\":100}",
                "sig-1",
                1_700_000_000_000L,
                1_700_000_000_123L
        );
    }
}

