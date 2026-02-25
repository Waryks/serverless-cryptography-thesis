package com.alexthesis.dynamo;

import com.alexthesis.dynamo.DedupRepository.DuplicateEventException;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemResponse;

import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link DedupRepository}.
 * The {@link DynamoDbClient} is mocked — no AWS calls are made.
 */
@ExtendWith(MockitoExtension.class)
class DedupRepositoryTest {

    private static final String TABLE    = "thesis-dedup";
    private static final long   TTL_SECS = 86400L;

    @Mock
    DynamoDbClient dynamoDbClient;

    DedupRepository dedupRepository;

    @BeforeEach
    void setUp() {
        dedupRepository = new DedupRepository(dynamoDbClient, TABLE, TTL_SECS);
    }

    @SuppressWarnings("unchecked")
    private void stubPutItemSuccess() {
        when(dynamoDbClient.putItem(any(Consumer.class))).thenReturn(PutItemResponse.builder().build());
    }

    @Test
    @SuppressWarnings("unchecked")
    void checkAndInsert_newEvent_invokesClientOnce() {
        stubPutItemSuccess();
        dedupRepository.checkAndInsert(buildContent("evt-new"));
        verify(dynamoDbClient, times(1)).putItem(any(Consumer.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void checkAndInsert_newEvent_writesToCorrectTable() {
        doAnswer(invocation -> {
            Consumer<PutItemRequest.Builder> consumer = invocation.getArgument(0);
            PutItemRequest.Builder builder = PutItemRequest.builder();
            consumer.accept(builder);
            assertThat(builder.build().tableName()).isEqualTo(TABLE);
            return PutItemResponse.builder().build();
        }).when(dynamoDbClient).putItem(any(Consumer.class));

        dedupRepository.checkAndInsert(buildContent("evt-table-check"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void checkAndInsert_newEvent_requestContainsEventIdAndTtl() {
        // Use doAnswer to capture the actual PutItemRequest built by the lambda
        long before = System.currentTimeMillis() / 1000L;

        doAnswer(invocation -> {
            Consumer<PutItemRequest.Builder> consumer = invocation.getArgument(0);
            PutItemRequest.Builder builder = PutItemRequest.builder();
            consumer.accept(builder);
            PutItemRequest req = builder.build();

            assertThat(req.tableName()).isEqualTo(TABLE);
            assertThat(req.item()).containsKey("eventId");
            assertThat(req.item().get("eventId").s()).isEqualTo("evt-attrs");
            assertThat(req.item()).containsKey("ttl");
            assertThat(Long.parseLong(req.item().get("ttl").n())).isGreaterThanOrEqualTo(before + TTL_SECS);
            assertThat(req.conditionExpression()).isEqualTo("attribute_not_exists(eventId)");

            return PutItemResponse.builder().build();
        }).when(dynamoDbClient).putItem(any(Consumer.class));

        dedupRepository.checkAndInsert(buildContent("evt-attrs"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void checkAndInsert_requestUsesConditionalExpression() {
        doAnswer(invocation -> {
            Consumer<PutItemRequest.Builder> consumer = invocation.getArgument(0);
            PutItemRequest.Builder builder = PutItemRequest.builder();
            consumer.accept(builder);
            assertThat(builder.build().conditionExpression()).isEqualTo("attribute_not_exists(eventId)");
            return PutItemResponse.builder().build();
        }).when(dynamoDbClient).putItem(any(Consumer.class));

        dedupRepository.checkAndInsert(buildContent("evt-cond"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void checkAndInsert_duplicateEvent_throwsDuplicateEventException() {
        when(dynamoDbClient.putItem(any(Consumer.class)))
                .thenThrow(ConditionalCheckFailedException.builder()
                        .message("The conditional request failed")
                        .build());

        assertThatThrownBy(() -> dedupRepository.checkAndInsert(buildContent("evt-dup")))
                .isInstanceOf(DuplicateEventException.class)
                .hasMessageContaining("evt-dup");
    }

    @Test
    @SuppressWarnings("unchecked")
    void checkAndInsert_duplicateEvent_causeIsConditionalCheckFailedException() {
        ConditionalCheckFailedException cause = ConditionalCheckFailedException.builder()
                .message("condition failed")
                .build();
        when(dynamoDbClient.putItem(any(Consumer.class))).thenThrow(cause);

        assertThatThrownBy(() -> dedupRepository.checkAndInsert(buildContent("evt-cause")))
                .isInstanceOf(DuplicateEventException.class)
                .hasCause(cause);
    }

    @Test
    @SuppressWarnings("unchecked")
    void checkAndInsert_dynamoDbThrows_propagatesException() {
        when(dynamoDbClient.putItem(any(Consumer.class)))
                .thenThrow(new RuntimeException("DynamoDB unavailable"));

        assertThatThrownBy(() -> dedupRepository.checkAndInsert(buildContent("evt-err")))
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

