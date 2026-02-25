package com.alexthesis.crypto;

import com.alexthesis.messaging.SignedContent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.enterprise.context.ApplicationScoped;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

/**
 * Produces cryptographic signatures for a {@link SignedContent} payload.
 * Supports HMAC-SHA256, RSA-PSS-SHA256, and ECDSA-P256-SHA256.
 *
 * <h2>Canonical serialisation</h2>
 * The content record is serialised deterministically by configuring the mapper
 * with {@link SerializationFeature#ORDER_MAP_ENTRIES_BY_KEYS}, which sorts all
 * fields alphabetically before converting to bytes. This ensures that the same
 * logical content always produces the same byte sequence regardless of insertion order.
 */
@ApplicationScoped
public class SignatureService {

    private final ObjectMapper canonicalMapper;

    public SignatureService(ObjectMapper objectMapper) {
        this.canonicalMapper = objectMapper.copy()
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    }

    /**
     * Signs the given {@link SignedContent} using the key material from {@code secret}.
     * The algorithm is determined by {@link SignedContent#algorithm()}.
     *
     * @param content the event content to sign
     * @param secret  the key secret fetched from Secrets Manager for {@link SignedContent#keyId()}
     * @return Base64-encoded signature string, ready to be set on {@link com.alexthesis.messaging.SignedEvent}
     */
    public String sign(SignedContent content, KeySecret secret) {
        byte[] canonicalBytes = canonicalise(content);
        byte[] rawSignature = switch (content.algorithm()) {
            case HMAC_SHA256 -> hmac(canonicalBytes, secret.keyMaterial());
            case RSA_PSS_SHA256 -> rsaPssSign(canonicalBytes, secret.keyMaterial());
            case ECDSA_P256_SHA256 -> asymmetricSign(canonicalBytes, secret.keyMaterial());
        };

        return Base64.getEncoder().encodeToString(rawSignature);
    }

    /**
     * Produces a deterministic UTF-8 byte representation of a {@link SignedContent}.
     * Fields are ordered alphabetically so that the byte sequence is stable
     * across JVM invocations and Jackson versions.
     */
    private byte[] canonicalise(SignedContent content) {
        try {
            return canonicalMapper.writeValueAsBytes(content);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialise SignedContent canonically", e);
        }
    }

    /**
     * Computes an HMAC-SHA256 MAC over {@code data} using a raw symmetric key
     * stored as Base64 in {@code base64Key}.
     */
    private byte[] hmac(byte[] data, String base64Key) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 signing failed", e);
        }
    }

    /**
     * Signs {@code data} with RSA-PSS using SHA-256 as both the hash and MGF1 digest,
     * with a salt length of 32 bytes.
     * <p>
     * {@link PSSParameterSpec} must be set explicitly — the JDK does not apply defaults
     * for {@code RSASSA-PSS} unlike {@code SHA256withRSA/PSS}.
     */
    private byte[] rsaPssSign(byte[] data, String base64Der) {
        try {
            byte[] derBytes = Base64.getDecoder().decode(stripPemHeaders(base64Der));
            PrivateKey privateKey = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(derBytes));

            PSSParameterSpec pssParams = new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

            Signature signer = Signature.getInstance("RSASSA-PSS");
            signer.setParameter(pssParams);
            signer.initSign(privateKey);
            signer.update(data);
            return signer.sign();
        } catch (Exception e) {
            throw new RuntimeException("RSASSA-PSS signing failed", e);
        }
    }

    /**
     * Signs {@code data} with a PKCS#8 private key encoded as Base64 (or PEM).
     * PEM headers are stripped automatically before decoding, so both raw Base64
     * DER and standard PEM inputs are accepted.
     *
     * @param data      the canonical bytes to sign
     * @param base64Der the Base64-encoded PKCS#8 DER private key (or PEM with headers)
     */
    private byte[] asymmetricSign(byte[] data, String base64Der) {
        try {
            byte[] derBytes = Base64.getDecoder().decode(
                    stripPemHeaders(base64Der)
            );
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(derBytes);
            PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(keySpec);

            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(privateKey);
            signer.update(data);

            return signer.sign();
        } catch (Exception e) {
            throw new RuntimeException("SHA256withECDSA signing failed", e);
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

