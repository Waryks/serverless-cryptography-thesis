package com.alexthesis.crypto;

import com.alexthesis.messaging.SignedContent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.enterprise.context.ApplicationScoped;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Verifies cryptographic signatures for a {@link SignedContent} payload.
 * Supports HMAC-SHA256, RSA-PSS-SHA256, and ECDSA-P256-SHA256.
 *
 * <h2>Canonical serialisation</h2>
 * Uses the same deterministic byte representation as the producer's {@code SignatureService}:
 * {@link SerializationFeature#ORDER_MAP_ENTRIES_BY_KEYS} sorts record fields alphabetically,
 * ensuring the byte sequence is identical on both sides of the pipeline.
 */
@ApplicationScoped
public class VerificationService {

    private final ObjectMapper canonicalMapper;

    public VerificationService(ObjectMapper objectMapper) {
        this.canonicalMapper = objectMapper.copy()
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    }

    /**
     * Verifies the signature on a {@link SignedContent} against the key material in {@code secret}.
     * The algorithm is determined by {@link SignedContent#algorithm()}.
     *
     * @param content      the event content that was signed by the producer
     * @param signatureB64 the Base64-encoded signature from {@link com.alexthesis.messaging.SignedEvent#signatureB64()}
     * @param secret       the key secret fetched from Secrets Manager for {@link SignedContent#keyId()}
     * @return {@code true} if the signature is valid, {@code false} otherwise
     */
    public boolean verifySignature(SignedContent content, String signatureB64, KeySecret secret) {
        byte[] canonicalBytes = canonicalise(content);
        byte[] signatureBytes = Base64.getDecoder().decode(signatureB64);

        return switch (content.algorithm()) {
            case HMAC_SHA256 -> verifyHmac(canonicalBytes, signatureBytes, secret.keyMaterial());
            case RSA_PSS_SHA256 -> verifyRsaPss(canonicalBytes, signatureBytes, secret.keyMaterial());
            case ECDSA_P256_SHA256 -> verifyEcdsa(canonicalBytes, signatureBytes, secret.keyMaterial());
        };
    }

    /**
     * Produces the same deterministic byte representation as the producer.
     * Must stay in sync with {@code SignatureService#canonicalise} on the producer side.
     */
    private byte[] canonicalise(SignedContent content) {
        try {
            return canonicalMapper.writeValueAsBytes(content);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialise SignedContent canonically", e);
        }
    }

    /**
     * Recomputes the HMAC-SHA256 MAC and compares it in constant time to prevent timing attacks.
     */
    private boolean verifyHmac(byte[] data, byte[] expectedSignature, String base64Key) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
            byte[] computed = mac.doFinal(data);

            return MessageDigest.isEqual(computed, expectedSignature);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 verification failed", e);
        }
    }

    /**
     * Verifies an RSA-PSS signature using the X.509-encoded public key in {@code base64Der}.
     * PSS parameters (SHA-256, MGF1+SHA-256, saltLen=32) must match those used during signing.
     */
    private boolean verifyRsaPss(byte[] data, byte[] signature, String base64Der) {
        try {
            PublicKey publicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(
                            Base64.getDecoder().decode(stripPemHeaders(base64Der))));

            PSSParameterSpec pssParams = new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

            Signature verifier = Signature.getInstance("RSASSA-PSS");
            verifier.setParameter(pssParams);
            verifier.initVerify(publicKey);
            verifier.update(data);

            return verifier.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException("RSASSA-PSS verification failed", e);
        }
    }

    /**
     * Verifies an ECDSA P-256 signature using the X.509-encoded public key in {@code base64Der}.
     */
    private boolean verifyEcdsa(byte[] data, byte[] signature, String base64Der) {
        try {
            PublicKey publicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(
                            Base64.getDecoder().decode(stripPemHeaders(base64Der))));

            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(data);

            return verifier.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException("SHA256withECDSA verification failed", e);
        }
    }

    /**
     * Strips PEM header/footer lines and whitespace so the remaining string
     * is pure Base64-encoded DER — works for both raw-Base64 and PEM inputs.
     */
    private String stripPemHeaders(String pem) {
        return pem.replaceAll("-----[^-]+-----", "")
                  .replaceAll("\\s", "");
    }
}

