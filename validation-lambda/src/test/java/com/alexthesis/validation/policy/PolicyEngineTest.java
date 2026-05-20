package com.alexthesis.validation.policy;

import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.AuditReason;
import com.alexthesis.messaging.SignedContent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PolicyEngineTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void evaluate_matchingPolicy_allowsEvent() {
        PolicyResolver resolver = mock(PolicyResolver.class);
        SecurityPolicy policy = new SecurityPolicy("strict-rsa", Algorithm.RSA_PSS_SHA256, true, 300_000L, true, false, true);
        SignedContent content = content(Algorithm.RSA_PSS_SHA256, "thesis/rsa/current");
        when(resolver.resolve(content)).thenReturn(policy);

        PolicyEngine engine = new PolicyEngine(resolver);
        PolicyValidationResult result = engine.evaluate(content);

        assertTrue(result.allowed());
        assertEquals(policy, result.policy());
    }

    @Test
    void evaluate_algorithmMismatch_rejectsEvent() {
        PolicyEngine engine = new PolicyEngine(mock(PolicyResolver.class));
        SecurityPolicy policy = new SecurityPolicy("strict-rsa", Algorithm.RSA_PSS_SHA256, true, 300_000L, true, false, true);
        SignedContent content = content(Algorithm.HMAC_SHA256, "thesis/hmac/current");

        PolicyValidationResult result = engine.evaluate(policy, content);

        assertFalse(result.allowed());
        assertEquals(AuditReason.ALGORITHM_MISMATCH, result.rejectionReason());
    }

    @Test
    void evaluate_strictValidation_rejectsUnexpectedKeyId() {
        PolicyEngine engine = new PolicyEngine(mock(PolicyResolver.class));
        SecurityPolicy policy = new SecurityPolicy("strict-rsa", Algorithm.RSA_PSS_SHA256, true, 300_000L, true, false, true);
        SignedContent content = content(Algorithm.RSA_PSS_SHA256, "thesis/hmac/current");

        PolicyValidationResult result = engine.evaluate(policy, content);

        assertFalse(result.allowed());
        assertEquals(AuditReason.POLICY_REJECTED, result.rejectionReason());
    }

    @Test
    void resolvePreviousKeyId_transformsCurrentSuffix() {
        PolicyEngine engine = new PolicyEngine(mock(PolicyResolver.class));

        assertEquals("thesis/hmac/previous", engine.resolvePreviousKeyId("thesis/hmac/current"));
        assertEquals("thesis/hmac-previous", engine.resolvePreviousKeyId("thesis/hmac-current"));
    }

    private SignedContent content(Algorithm algorithm, String keyId) {
        return new SignedContent(
                "event-1",
                System.currentTimeMillis(),
                algorithm,
                keyId,
                mapper.createObjectNode().put("data", "test")
        );
    }
}

