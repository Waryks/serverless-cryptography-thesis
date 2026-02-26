package com.alexthesis.lambda;

import com.alexthesis.crypto.helpers.KeySecret;
import com.alexthesis.crypto.TestKeyPairFixtures;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsResponse;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Component tests for the consumer pipeline.
 * The full Quarkus CDI container is started; only the AWS SDK clients are replaced
 * with Mockito mocks via {@link InjectMock}.
 *
 * <p>Each test signs the event with the private key and stores the public key in the
 * mocked Secrets Manager response, exercising the full verification flow end-to-end.
 */
@QuarkusTest
class ConsumerComponentTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject
    ConsumerService consumerService;

    @InjectMock
    SecretsManagerClient secretsManagerClient;

    @InjectMock
    DynamoDbClient dynamoDbClient;

    @Test
    void processMessage_hmac_validSignatureIsAccepted() throws Exception {
        String keyId = "hmac-key-1";
        String keyB64 = TestKeyPairFixtures.hmacKeyB64();

        SignedContent content = buildContent("evt-hmac-1", Algorithm.HMAC_SHA256, keyId);
        String signatureB64 = signHmac(content, keyB64);

        stubSecretsManager(keyId, Algorithm.HMAC_SHA256, keyB64);
        stubDynamoDb();
        assertThatCode(() -> consumerService.processMessage(toJson(content, signatureB64)))
                .doesNotThrowAnyException();
    }

    @Test
    void processMessage_hmac_tamperedSignatureIsRejected() throws Exception {
        String keyId = "hmac-key-1";
        String keyB64 = TestKeyPairFixtures.hmacKeyB64();

        SignedContent content = buildContent("evt-hmac-2", Algorithm.HMAC_SHA256, keyId);
        stubSecretsManager(keyId, Algorithm.HMAC_SHA256, keyB64);
        stubDynamoDb();

        assertThatThrownBy(() -> consumerService.processMessage(toJson(content, "aW52YWxpZA==")))
                .isInstanceOf(ConsumerService.InvalidSignatureException.class);
    }

    @Test
    void processMessage_rsa_validSignatureIsAccepted() throws Exception {
        String keyId = "rsa-key-1";
        TestKeyPairFixtures.KeyMaterial keys = TestKeyPairFixtures.rsaKeyPair();

        SignedContent content = buildContent("evt-rsa-1", Algorithm.RSA_PSS_SHA256, keyId);
        String signatureB64 = signRsaPss(content, keys.privateKeyB64());

        stubSecretsManager(keyId, Algorithm.RSA_PSS_SHA256, keys.publicKeyB64());
        stubDynamoDb();
        assertThatCode(() -> consumerService.processMessage(toJson(content, signatureB64)))
                .doesNotThrowAnyException();
    }

    @Test
    void processMessage_ecdsa_validSignatureIsAccepted() throws Exception {
        String keyId = "ec-key-1";
        TestKeyPairFixtures.KeyMaterial keys = TestKeyPairFixtures.ecKeyPair();

        SignedContent content = buildContent("evt-ec-1", Algorithm.ECDSA_P256_SHA256, keyId);
        String signatureB64 = signEcdsa(content, keys.privateKeyB64());

        stubSecretsManager(keyId, Algorithm.ECDSA_P256_SHA256, keys.publicKeyB64());
        stubDynamoDb();
        assertThatCode(() -> consumerService.processMessage(toJson(content, signatureB64)))
                .doesNotThrowAnyException();
    }

    @Test
    void processMessage_expiredTimestamp_isRejected() throws Exception {
        String keyId = "hmac-key-1";
        String keyB64 = TestKeyPairFixtures.hmacKeyB64();

        long expiredTimestamp = System.currentTimeMillis() - 400_000L;
        SignedContent content = buildContent("evt-old", Algorithm.HMAC_SHA256, keyId, expiredTimestamp);
        String signatureB64 = signHmac(content, keyB64);

        stubSecretsManager(keyId, Algorithm.HMAC_SHA256, keyB64);
        stubDynamoDb();
        assertThatThrownBy(() -> consumerService.processMessage(toJson(content, signatureB64)))
                .isInstanceOf(ConsumerService.ReplayWindowException.class);
    }

    private void stubSecretsManager(String keyId, Algorithm algorithm, String keyMaterial) throws Exception {
        KeySecret secret = new KeySecret(keyId, algorithm.name(), keyMaterial);
        GetSecretValueResponse response = GetSecretValueResponse.builder()
                .secretString(MAPPER.writeValueAsString(secret))
                .build();
        when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(response);
    }

    private void stubDynamoDb() {
        when(dynamoDbClient.transactWriteItems(any(TransactWriteItemsRequest.class)))
                .thenReturn(TransactWriteItemsResponse.builder().build());
    }

    private SignedContent buildContent(String eventId, Algorithm algorithm, String keyId) {
        return buildContent(eventId, algorithm, keyId, System.currentTimeMillis());
    }

    private SignedContent buildContent(String eventId, Algorithm algorithm, String keyId, long timestamp) {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("benchmarkId", "bench-1");
        return new SignedContent(eventId, timestamp, algorithm, keyId, payload);
    }

    private String toJson(SignedContent content, String signatureB64) throws Exception {
        return MAPPER.writeValueAsString(new SignedEvent(content, signatureB64));
    }

    private String signHmac(SignedContent content, String keyB64) throws Exception {
        byte[] data = canonicalise(content);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(Base64.getDecoder().decode(keyB64), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(data));
    }

    private String signRsaPss(SignedContent content, String privateKeyB64) throws Exception {
        PrivateKey key = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyB64)));
        PSSParameterSpec pss = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        Signature signer = Signature.getInstance("RSASSA-PSS");
        signer.setParameter(pss);
        signer.initSign(key);
        signer.update(canonicalise(content));
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    private String signEcdsa(SignedContent content, String privateKeyB64) throws Exception {
        PrivateKey key = KeyFactory.getInstance("EC")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyB64)));
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(key);
        signer.update(canonicalise(content));
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    private byte[] canonicalise(SignedContent content) throws Exception {
        return new ObjectMapper()
                .copy()
                .configure(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .writeValueAsBytes(content);
    }
}

