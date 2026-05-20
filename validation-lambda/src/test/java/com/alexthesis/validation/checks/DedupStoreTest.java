package com.alexthesis.validation.checks;

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
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DedupStoreTest {

    private static final String TABLE = "thesis-dedup";
    private static final long TTL_SECONDS = 86_400L;

    @Mock
    DynamoDbClient dynamoDbClient;

    private DedupStore dedupStore;

    @BeforeEach
    void setUp() {
        dedupStore = new DedupStore(dynamoDbClient, TABLE, true, TTL_SECONDS);
    }

    @Test
    void isNewEvent_whenEnabledAndNew_persistsRecordAndReturnsTrue() {
        when(dynamoDbClient.putItem(any(PutItemRequest.class))).thenReturn(PutItemResponse.builder().build());

        long before = System.currentTimeMillis() / 1000L;
        boolean result = dedupStore.isNewEvent(buildContent("evt-new"));

        assertThat(result).isTrue();
        ArgumentCaptor<PutItemRequest> captor = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(captor.capture());

        PutItemRequest request = captor.getValue();
        assertThat(request.tableName()).isEqualTo(TABLE);
        assertThat(request.conditionExpression()).isEqualTo("attribute_not_exists(eventId)");
        assertThat(request.item()).containsKeys("eventId", "processedAtEpochMs", "algorithm", "keyId", "ttl");
        assertThat(request.item().get("eventId").s()).isEqualTo("evt-new");
        assertThat(request.item().get("algorithm").s()).isEqualTo("HMAC_SHA256");
        assertThat(request.item().get("keyId").s()).isEqualTo("key-1");
        assertThat(Long.parseLong(request.item().get("processedAtEpochMs").n())).isGreaterThanOrEqualTo(before * 1000L);
        assertThat(Long.parseLong(request.item().get("ttl").n())).isGreaterThanOrEqualTo(before + TTL_SECONDS);
    }

    @Test
    void isNewEvent_whenDuplicate_returnsFalse() {
        when(dynamoDbClient.putItem(any(PutItemRequest.class)))
                .thenThrow(ConditionalCheckFailedException.builder().message("duplicate").build());

        boolean result = dedupStore.isNewEvent(buildContent("evt-dup"));

        assertThat(result).isFalse();
        verify(dynamoDbClient).putItem(any(PutItemRequest.class));
    }

    @Test
    void isNewEvent_whenDisabled_skipsDynamoDbAndReturnsTrue() {
        dedupStore = new DedupStore(dynamoDbClient, TABLE, false, TTL_SECONDS);

        boolean result = dedupStore.isNewEvent(buildContent("evt-disabled"));

        assertThat(result).isTrue();
        verify(dynamoDbClient, never()).putItem(any(PutItemRequest.class));
    }

    @Test
    void isNewEvent_whenInfrastructureFails_propagatesException() {
        when(dynamoDbClient.putItem(any(PutItemRequest.class)))
                .thenThrow(new RuntimeException("DynamoDB unavailable"));

        assertThatThrownBy(() -> dedupStore.isNewEvent(buildContent("evt-err")))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("DynamoDB unavailable");
    }

    private static SignedContent buildContent(String eventId) {
        return new SignedContent(
                eventId,
                System.currentTimeMillis(),
                Algorithm.HMAC_SHA256,
                "key-1",
                JsonNodeFactory.instance.objectNode().put("data", "value")
        );
    }
}


