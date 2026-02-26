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
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link VerificationService}.
 * Each test signs data with the private key and verifies with the corresponding public key,
 * mirroring the real producer → consumer flow.
 */
class VerificationServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private VerificationService verificationService;

    @BeforeEach
    void setUp() {
        verificationService = new VerificationService(MAPPER);
    }

    @Test
    void verify_Signature_hmac_validSignatureReturnsTrue() throws Exception {
        String keyB64 = TestKeyPairFixtures.hmacKeyB64();
        SignedContent content = buildContent(Algorithm.HMAC_SHA256, "key-1");
        String signatureB64 = signHmac(content, keyB64);

        KeySecret secret = new KeySecret("key-1", "HMAC_SHA256", keyB64);
        assertThat(verificationService.verifySignature(content, signatureB64, secret)).isTrue();
    }

    @Test
    void verify_Signature_hmac_tamperedPayloadReturnsFalse() throws Exception {
        String keyB64 = TestKeyPairFixtures.hmacKeyB64();
        SignedContent original = buildContent(Algorithm.HMAC_SHA256, "key-1");
        String signatureB64 = signHmac(original, keyB64);

        // Different content — signature no longer matches
        SignedContent tampered = buildContent(Algorithm.HMAC_SHA256, "key-1", "tampered");
        KeySecret secret = new KeySecret("key-1", "HMAC_SHA256", keyB64);

        assertThat(verificationService.verifySignature(tampered, signatureB64, secret)).isFalse();
    }

    @Test
    void verify_Signature_hmac_wrongKeyReturnsFalse() throws Exception {
        String signingKey = TestKeyPairFixtures.hmacKeyB64();
        String wrongKey   = TestKeyPairFixtures.hmacKeyB64();
        SignedContent content = buildContent(Algorithm.HMAC_SHA256, "key-1");
        String signatureB64 = signHmac(content, signingKey);

        KeySecret secret = new KeySecret("key-1", "HMAC_SHA256", wrongKey);
        assertThat(verificationService.verifySignature(content, signatureB64, secret)).isFalse();
    }

    @Test
    void verify_Signature_rsa_validSignatureReturnsTrue() throws Exception {
        TestKeyPairFixtures.KeyMaterial keys = TestKeyPairFixtures.rsaKeyPair();
        SignedContent content = buildContent(Algorithm.RSA_PSS_SHA256, "rsa-key");
        String signatureB64 = signRsaPss(content, keys.privateKeyB64());

        KeySecret secret = new KeySecret("rsa-key", "RSA_PSS_SHA256", keys.publicKeyB64());
        assertThat(verificationService.verifySignature(content, signatureB64, secret)).isTrue();
    }

    @Test
    void verify_Signature_rsa_tamperedPayloadReturnsFalse() throws Exception {
        TestKeyPairFixtures.KeyMaterial keys = TestKeyPairFixtures.rsaKeyPair();
        SignedContent original = buildContent(Algorithm.RSA_PSS_SHA256, "rsa-key");
        String signatureB64 = signRsaPss(original, keys.privateKeyB64());

        SignedContent tampered = buildContent(Algorithm.RSA_PSS_SHA256, "rsa-key", "tampered");
        KeySecret secret = new KeySecret("rsa-key", "RSA_PSS_SHA256", keys.publicKeyB64());

        assertThat(verificationService.verifySignature(tampered, signatureB64, secret)).isFalse();
    }

    @Test
    void verify_Signature_rsa_invalidKeyMaterialThrows() {
        SignedContent content = buildContent(Algorithm.RSA_PSS_SHA256, "rsa-key");
        KeySecret secret = new KeySecret("rsa-key", "RSA_PSS_SHA256", "not-valid-base64!!!");

        assertThatThrownBy(() -> verificationService.verifySignature(content, "AAAA", secret))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void verify_Signature_ecdsa_validSignatureReturnsTrue() throws Exception {
        TestKeyPairFixtures.KeyMaterial keys = TestKeyPairFixtures.ecKeyPair();
        SignedContent content = buildContent(Algorithm.ECDSA_P256_SHA256, "ec-key");
        String signatureB64 = signEcdsa(content, keys.privateKeyB64());

        KeySecret secret = new KeySecret("ec-key", "ECDSA_P256_SHA256", keys.publicKeyB64());
        assertThat(verificationService.verifySignature(content, signatureB64, secret)).isTrue();
    }

    @Test
    void verify_Signature_ecdsa_tamperedPayloadReturnsFalse() throws Exception {
        TestKeyPairFixtures.KeyMaterial keys = TestKeyPairFixtures.ecKeyPair();
        SignedContent original = buildContent(Algorithm.ECDSA_P256_SHA256, "ec-key");
        String signatureB64 = signEcdsa(original, keys.privateKeyB64());

        SignedContent tampered = buildContent(Algorithm.ECDSA_P256_SHA256, "ec-key", "tampered");
        KeySecret secret = new KeySecret("ec-key", "ECDSA_P256_SHA256", keys.publicKeyB64());

        assertThat(verificationService.verifySignature(tampered, signatureB64, secret)).isFalse();
    }

    private SignedContent buildContent(Algorithm algorithm, String keyId) {
        return buildContent(algorithm, keyId, "test-value");
    }

    private SignedContent buildContent(Algorithm algorithm, String keyId, String payloadValue) {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("data", payloadValue);
        return new SignedContent("evt-1", 1_700_000_000_000L, algorithm, keyId, payload);
    }

    private String signHmac(SignedContent content, String keyB64) throws Exception {
        byte[] canonicalBytes = canonicalise(content);
        byte[] keyBytes = Base64.getDecoder().decode(keyB64);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(canonicalBytes));
    }

    private String signRsaPss(SignedContent content, String privateKeyB64) throws Exception {
        byte[] canonicalBytes = canonicalise(content);
        PrivateKey privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyB64)));
        PSSParameterSpec pssParams = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        Signature signer = Signature.getInstance("RSASSA-PSS");
        signer.setParameter(pssParams);
        signer.initSign(privateKey);
        signer.update(canonicalBytes);
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    private String signEcdsa(SignedContent content, String privateKeyB64) throws Exception {
        byte[] canonicalBytes = canonicalise(content);
        PrivateKey privateKey = KeyFactory.getInstance("EC")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyB64)));
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update(canonicalBytes);
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    private byte[] canonicalise(SignedContent content) throws Exception {
        return new ObjectMapper()
                .copy()
                .configure(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .writeValueAsBytes(content);
    }
}

