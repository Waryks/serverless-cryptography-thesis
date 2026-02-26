package com.alexthesis.crypto;

import com.alexthesis.crypto.helpers.KeySecret;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link SignatureService}.
 * No Spring/Quarkus container — plain JUnit 5.
 */
class SignatureServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SignatureService signatureService;

    @BeforeEach
    void setUp() {
        signatureService = new SignatureService(MAPPER);
    }

    @Test
    void sign_hmac_returnsNonBlankBase64() {
        String keyB64 = TestKeyFixtures.hmacKeyB64();
        KeySecret secret = new KeySecret("key-1", "HMAC_SHA256", keyB64);
        SignedContent content = buildContent(Algorithm.HMAC_SHA256, "key-1");

        String signature = signatureService.sign(content, secret);

        assertThat(signature).isNotBlank();
        assertThat(Base64.getDecoder().decode(signature)).hasSize(32); // HMAC-SHA256 is always 32 bytes
    }

    @Test
    void sign_hmac_isDeterministic() {
        String keyB64 = TestKeyFixtures.hmacKeyB64();
        KeySecret secret = new KeySecret("key-1", "HMAC_SHA256", keyB64);
        SignedContent content = buildContent(Algorithm.HMAC_SHA256, "key-1");

        String sig1 = signatureService.sign(content, secret);
        String sig2 = signatureService.sign(content, secret);

        assertThat(sig1).isEqualTo(sig2);
    }

    @Test
    void sign_hmac_canBeVerifiedManually() throws Exception {
        String keyB64 = TestKeyFixtures.hmacKeyB64();
        KeySecret secret = new KeySecret("key-1", "HMAC_SHA256", keyB64);
        SignedContent content = buildContent(Algorithm.HMAC_SHA256, "key-1");

        String signatureB64 = signatureService.sign(content, secret);

        // Reproduce what SignatureService does internally and compare
        byte[] keyBytes = Base64.getDecoder().decode(keyB64);
        byte[] canonicalBytes = new com.fasterxml.jackson.databind.ObjectMapper()
                .copy()
                .configure(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .writeValueAsBytes(content);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
        String expected = Base64.getEncoder().encodeToString(mac.doFinal(canonicalBytes));

        assertThat(signatureB64).isEqualTo(expected);
    }

    @Test
    void sign_hmac_differentKeyProducesDifferentSignature() {
        SignedContent content = buildContent(Algorithm.HMAC_SHA256, "key-1");
        KeySecret secret1 = new KeySecret("key-1", "HMAC_SHA256", TestKeyFixtures.hmacKeyB64());
        KeySecret secret2 = new KeySecret("key-1", "HMAC_SHA256", TestKeyFixtures.hmacKeyB64());

        assertThat(signatureService.sign(content, secret1))
                .isNotEqualTo(signatureService.sign(content, secret2));
    }

    @Test
    void sign_rsa_returnsValidSignature() throws Exception {
        var kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        var kp = kpg.generateKeyPair();
        String privateKeyB64 = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());

        KeySecret secret = new KeySecret("rsa-key", "RSA_PSS_SHA256", privateKeyB64);
        SignedContent content = buildContent(Algorithm.RSA_PSS_SHA256, "rsa-key");

        String signatureB64 = signatureService.sign(content, secret);

        assertThat(signatureB64).isNotBlank();
        verifyRsa(content, signatureB64, kp.getPublic());
    }

    @Test
    void sign_rsa_invalidKeyMaterialThrows() {
        KeySecret secret = new KeySecret("rsa-key", "RSA_PSS_SHA256", "not-valid-base64!!!");
        SignedContent content = buildContent(Algorithm.RSA_PSS_SHA256, "rsa-key");

        assertThatThrownBy(() -> signatureService.sign(content, secret))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void sign_ecdsa_returnsValidSignature() throws Exception {
        var kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        var kp = kpg.generateKeyPair();
        String privateKeyB64 = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());

        KeySecret secret = new KeySecret("ec-key", "ECDSA_P256_SHA256", privateKeyB64);
        SignedContent content = buildContent(Algorithm.ECDSA_P256_SHA256, "ec-key");

        String signatureB64 = signatureService.sign(content, secret);

        assertThat(signatureB64).isNotBlank();
        verifyEcdsa(content, signatureB64, kp.getPublic());
    }

    @Test
    void sign_hmac_differentContentProducesDifferentSignature() {
        String keyB64 = TestKeyFixtures.hmacKeyB64();
        KeySecret secret = new KeySecret("key-1", "HMAC_SHA256", keyB64);

        ObjectNode payload1 = MAPPER.createObjectNode();
        payload1.put("data", "value-A");
        ObjectNode payload2 = MAPPER.createObjectNode();
        payload2.put("data", "value-B");

        SignedContent content1 = new SignedContent("evt-1", 1000L, Algorithm.HMAC_SHA256, "key-1", payload1);
        SignedContent content2 = new SignedContent("evt-1", 1000L, Algorithm.HMAC_SHA256, "key-1", payload2);

        assertThat(signatureService.sign(content1, secret))
                .isNotEqualTo(signatureService.sign(content2, secret));
    }

    private SignedContent buildContent(Algorithm algorithm, String keyId) {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("message", "test");
        return new SignedContent("evt-id-1", 1_700_000_000_000L, algorithm, keyId, payload);
    }

    private void verifyRsa(SignedContent content, String signatureB64, PublicKey publicKey) throws Exception {
        byte[] canonicalBytes = new ObjectMapper()
                .copy()
                .configure(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .writeValueAsBytes(content);
        PSSParameterSpec pssParams = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        Signature verifier = Signature.getInstance("RSASSA-PSS");
        verifier.setParameter(pssParams);
        verifier.initVerify(publicKey);
        verifier.update(canonicalBytes);
        assertThat(verifier.verify(Base64.getDecoder().decode(signatureB64))).isTrue();
    }

    private void verifyEcdsa(SignedContent content, String signatureB64, PublicKey publicKey) throws Exception {
        byte[] canonicalBytes = new ObjectMapper()
                .copy()
                .configure(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .writeValueAsBytes(content);
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(canonicalBytes);
        assertThat(verifier.verify(Base64.getDecoder().decode(signatureB64))).isTrue();
    }
}




