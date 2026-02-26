package com.alexthesis.lambda;

import com.alexthesis.crypto.KeySecret;
import com.alexthesis.crypto.SecretService;
import com.alexthesis.crypto.VerificationService;
import com.alexthesis.dynamo.DedupRepository;
import com.alexthesis.dynamo.LedgerRepository;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsResponse;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ConsumerServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final KeySecret DUMMY_SECRET = new KeySecret("key-1", "HMAC_SHA256", "dGVzdA==");

    @Mock SecretService      secretService;
    @Mock VerificationService verificationService;
    @Mock DedupRepository    dedupRepository;
    @Mock LedgerRepository   ledgerRepository;
    @Mock DynamoDbClient     dynamoDbClient;

    private ConsumerService consumerService;

    @BeforeEach
    void setUp() {
        consumerService = new ConsumerService(
                secretService, verificationService,
                dedupRepository, ledgerRepository,
                dynamoDbClient,
                true, 300_000L);
        // Default: repositories return a dummy TransactWriteItem and the transaction succeeds.
        // Marked lenient because tests that throw before the transaction (invalid sig, expired
        // timestamp, malformed JSON, etc.) will not consume these stubs.
        lenient().when(dedupRepository.buildTransactItem(any())).thenReturn(TransactWriteItem.builder().build());
        lenient().when(ledgerRepository.buildTransactItem(any())).thenReturn(TransactWriteItem.builder().build());
        lenient().when(dynamoDbClient.transactWriteItems(any(TransactWriteItemsRequest.class)))
                .thenReturn(TransactWriteItemsResponse.builder().build());
    }

    @Test
    void processMessage_validSignature_doesNotThrow() throws Exception {
        String body = buildMessageBody("evt-1", Algorithm.HMAC_SHA256, "key-1", System.currentTimeMillis());
        when(secretService.getSecret("key-1")).thenReturn(DUMMY_SECRET);
        when(verificationService.verifySignature(any(), any(), any())).thenReturn(true);

        assertThatCode(() -> consumerService.processMessage(body)).doesNotThrowAnyException();
    }

    @Test
    void processMessage_fetchesSecretUsingKeyIdFromContent() throws Exception {
        String body = buildMessageBody("evt-1", Algorithm.HMAC_SHA256, "the-key-id", System.currentTimeMillis());
        when(secretService.getSecret("the-key-id")).thenReturn(DUMMY_SECRET);
        when(verificationService.verifySignature(any(), any(), any())).thenReturn(true);

        consumerService.processMessage(body);

        verify(secretService).getSecret("the-key-id");
    }

    @Test
    void processMessage_passesCorrectSignatureThroughToVerifier() throws Exception {
        SignedContent content = buildContent("evt-1", Algorithm.HMAC_SHA256, "key-1", System.currentTimeMillis());
        SignedEvent event = new SignedEvent(content, "my-signature-b64");
        String body = MAPPER.writeValueAsString(event);

        when(secretService.getSecret("key-1")).thenReturn(DUMMY_SECRET);
        when(verificationService.verifySignature(any(), eq("my-signature-b64"), any())).thenReturn(true);

        assertThatCode(() -> consumerService.processMessage(body)).doesNotThrowAnyException();
        verify(verificationService).verifySignature(any(), eq("my-signature-b64"), any());
    }

    @Test
    void processMessage_invalidSignature_throwsInvalidSignatureException() throws Exception {
        String body = buildMessageBody("evt-1", Algorithm.HMAC_SHA256, "key-1", System.currentTimeMillis());
        when(secretService.getSecret("key-1")).thenReturn(DUMMY_SECRET);
        when(verificationService.verifySignature(any(), any(), any())).thenReturn(false);

        assertThatThrownBy(() -> consumerService.processMessage(body))
                .isInstanceOf(ConsumerService.InvalidSignatureException.class)
                .hasMessageContaining("evt-1");
    }

    @Test
    void processMessage_expiredTimestamp_throwsReplayWindowException() throws Exception {
        long expiredTimestamp = System.currentTimeMillis() - 400_000L; // older than 300s window
        String body = buildMessageBody("evt-old", Algorithm.HMAC_SHA256, "key-1", expiredTimestamp);
        when(secretService.getSecret("key-1")).thenReturn(DUMMY_SECRET);
        when(verificationService.verifySignature(any(), any(), any())).thenReturn(true);

        assertThatThrownBy(() -> consumerService.processMessage(body))
                .isInstanceOf(ConsumerService.ReplayWindowException.class);
    }

    @Test
    void processMessage_replayCheckDisabled_expiredTimestampDoesNotThrow() throws Exception {
        consumerService = new ConsumerService(
                secretService, verificationService,
                dedupRepository, ledgerRepository,
                dynamoDbClient,
                false, 300_000L);
        lenient().when(dedupRepository.buildTransactItem(any())).thenReturn(TransactWriteItem.builder().build());
        lenient().when(ledgerRepository.buildTransactItem(any())).thenReturn(TransactWriteItem.builder().build());
        lenient().when(dynamoDbClient.transactWriteItems(any(TransactWriteItemsRequest.class)))
                .thenReturn(TransactWriteItemsResponse.builder().build());
        long expiredTimestamp = System.currentTimeMillis() - 400_000L;
        String body = buildMessageBody("evt-old", Algorithm.HMAC_SHA256, "key-1", expiredTimestamp);
        when(secretService.getSecret("key-1")).thenReturn(DUMMY_SECRET);
        when(verificationService.verifySignature(any(), any(), any())).thenReturn(true);

        assertThatCode(() -> consumerService.processMessage(body)).doesNotThrowAnyException();
    }

    @Test
    void processMessage_malformedJson_throwsRuntimeException() {
        assertThatThrownBy(() -> consumerService.processMessage("not-valid-json{"))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void processMessage_secretServiceThrows_propagatesException() throws Exception {
        String body = buildMessageBody("evt-1", Algorithm.HMAC_SHA256, "key-1", System.currentTimeMillis());
        when(secretService.getSecret(any())).thenThrow(new RuntimeException("Secrets Manager unavailable"));

        assertThatThrownBy(() -> consumerService.processMessage(body))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Secrets Manager unavailable");
    }

    private String buildMessageBody(String eventId, Algorithm algorithm, String keyId, long timestamp) throws Exception {
        SignedContent content = buildContent(eventId, algorithm, keyId, timestamp);
        return MAPPER.writeValueAsString(new SignedEvent(content, "dummy-sig"));
    }

    private SignedContent buildContent(String eventId, Algorithm algorithm, String keyId, long timestamp) {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("data", "value");
        return new SignedContent(eventId, timestamp, algorithm, keyId, payload);
    }
}

