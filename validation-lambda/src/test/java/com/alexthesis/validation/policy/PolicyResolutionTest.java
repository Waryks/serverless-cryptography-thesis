package com.alexthesis.validation.policy;

import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.fasterxml.jackson.databind.JsonNode;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class PolicyResolutionTest {

    @Inject
    PolicyResolver policyResolver;

    @Test
    void resolve_hmacEvent_usesRelaxedPolicy() {
        SecurityPolicy policy = policyResolver.resolve(content(Algorithm.HMAC_SHA256, "thesis/hmac/current"));

        assertEquals("relaxed-hmac", policy.policyId());
        assertEquals(Algorithm.HMAC_SHA256, policy.allowedAlgorithm());
        assertFalse(policy.replayCheckEnabled());
        assertFalse(policy.dedupEnabled());
        assertTrue(policy.allowPreviousKey());
        assertFalse(policy.strictValidation());
    }

    @Test
    void resolve_rsaEvent_usesStrictPolicy() {
        SecurityPolicy policy = policyResolver.resolve(content(Algorithm.RSA_PSS_SHA256, "thesis/rsa/current"));

        assertEquals("strict-rsa", policy.policyId());
        assertEquals(Algorithm.RSA_PSS_SHA256, policy.allowedAlgorithm());
        assertTrue(policy.replayCheckEnabled());
        assertTrue(policy.dedupEnabled());
        assertFalse(policy.allowPreviousKey());
        assertTrue(policy.strictValidation());
    }

    private SignedContent content(Algorithm algorithm, String keyId) {
        JsonNode payload = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode().put("data", "test");
        return new SignedContent("event-1", System.currentTimeMillis(), algorithm, keyId, payload);
    }
}

