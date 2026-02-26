package com.alexthesis.lambda;

import com.alexthesis.crypto.helpers.KeySecret;
import com.alexthesis.crypto.TestKeyFixtures;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageResponse;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Component tests for the producer pipeline.
 * The full Quarkus CDI container is started; only the AWS SDK clients
 * (SQS and Secrets Manager) are replaced with Mockito mocks via {@link InjectMock}.
 *
 * <p>This validates that:
 * <ul>
 *   <li>CDI wiring is correct end-to-end</li>
 *   <li>The correct secret is fetched for each algorithm</li>
 *   <li>A non-blank signature is computed and forwarded to SQS</li>
 *   <li>The response contains the expected event ID</li>
 * </ul>
 */
@QuarkusTest
class ProducerComponentTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject
    ProducerHandler producerHandler;

    @InjectMock
    SecretsManagerClient secretsManagerClient;

    @InjectMock
    SqsClient sqsClient;

    /** Captures the request built by the consumer-lambda overload of {@code sendMessage}. */
    private final AtomicReference<SendMessageRequest> capturedRequest = new AtomicReference<>();

    @BeforeEach
    @SuppressWarnings("unchecked")
    void stubSqs() {
        capturedRequest.set(null);
        doAnswer(inv -> {
            Consumer<SendMessageRequest.Builder> consumer = inv.getArgument(0);
            SendMessageRequest.Builder builder = SendMessageRequest.builder();
            consumer.accept(builder);
            capturedRequest.set(builder.build());
            return SendMessageResponse.builder().messageId("mock-msg-id").build();
        }).when(sqsClient).sendMessage(any(Consumer.class));
    }

    @Test
    void handleRequest_hmac_producesResponseAndPublishesToSqs() throws Exception {
        String keyId = "hmac-key-1";
        stubSecretsManager(keyId, Algorithm.HMAC_SHA256, TestKeyFixtures.hmacKeyB64());

        SignedEvent input = buildEvent("evt-hmac-1", Algorithm.HMAC_SHA256, keyId);
        ProducerResponse response = producerHandler.handleRequest(input, null);

        assertThat(response.eventId()).isEqualTo("evt-hmac-1");
        assertThat(response.durationMs()).isGreaterThanOrEqualTo(0);
        verifySqsCalledWithNonBlankSignature();
    }

    @Test
    void handleRequest_rsa_producesResponseAndPublishesToSqs() throws Exception {
        String keyId = "rsa-key-1";
        stubSecretsManager(keyId, Algorithm.RSA_PSS_SHA256, TestKeyFixtures.rsaKeyB64());

        SignedEvent input = buildEvent("evt-rsa-1", Algorithm.RSA_PSS_SHA256, keyId);
        ProducerResponse response = producerHandler.handleRequest(input, null);

        assertThat(response.eventId()).isEqualTo("evt-rsa-1");
        verifySqsCalledWithNonBlankSignature();
    }

    @Test
    void handleRequest_ecdsa_producesResponseAndPublishesToSqs() throws Exception {
        String keyId = "ec-key-1";
        stubSecretsManager(keyId, Algorithm.ECDSA_P256_SHA256, TestKeyFixtures.ecKeyB64());

        SignedEvent input = buildEvent("evt-ec-1", Algorithm.ECDSA_P256_SHA256, keyId);
        ProducerResponse response = producerHandler.handleRequest(input, null);

        assertThat(response.eventId()).isEqualTo("evt-ec-1");
        verifySqsCalledWithNonBlankSignature();
    }

    private void stubSecretsManager(String keyId, Algorithm algorithm, String keyMaterial) throws Exception {
        KeySecret keySecret = new KeySecret(keyId, algorithm.name(), keyMaterial);
        String secretJson = MAPPER.writeValueAsString(keySecret);
        GetSecretValueResponse secretResponse = GetSecretValueResponse.builder()
                .secretString(secretJson)
                .build();
        when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                .thenReturn(secretResponse);
    }

    private void verifySqsCalledWithNonBlankSignature() throws Exception {
        SendMessageRequest request = capturedRequest.get();
        assertThat(request).isNotNull();
        SignedEvent published = MAPPER.readValue(request.messageBody(), SignedEvent.class);
        assertThat(published.signatureB64()).isNotBlank();
    }

    private SignedEvent buildEvent(String eventId, Algorithm algorithm, String keyId) {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("benchmarkId", "bench-1");
        payload.put("iteration", 1);
        SignedContent content = new SignedContent(eventId, System.currentTimeMillis(), algorithm, keyId, payload);
        return new SignedEvent(content, null);
    }
}




