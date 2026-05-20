package com.alexthesis.validation.policy;

import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.AuditReason;
import com.alexthesis.messaging.SignedContent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.Locale;

/**
 * Applies policy checks to validation events.
 *
 * <p>The engine does not perform cryptographic verification; it only decides
 * whether a message is allowed to proceed and which checks should be applied.
 */
@ApplicationScoped
public class PolicyEngine {

    private final PolicyResolver policyResolver;

    @Inject
    public PolicyEngine(PolicyResolver policyResolver) {
        this.policyResolver = policyResolver;
    }

    public PolicyValidationResult evaluate(SignedContent content) {
        SecurityPolicy policy = policyResolver.resolve(content);
        return evaluate(policy, content);
    }

    public PolicyValidationResult evaluate(SecurityPolicy policy, SignedContent content) {
        if (policy.allowedAlgorithm() != content.algorithm()) {
            return PolicyValidationResult.rejected(
                    policy,
                    AuditReason.ALGORITHM_MISMATCH,
                    "Policy %s requires %s but event used %s".formatted(
                            policy.policyId(), policy.allowedAlgorithm(), content.algorithm())
            );
        }

        if (policy.strictValidation() && !keyIdMatchesAlgorithm(content.keyId(), policy.allowedAlgorithm())) {
            return PolicyValidationResult.rejected(
                    policy,
                    AuditReason.POLICY_REJECTED,
                    "Strict policy %s rejected keyId %s for algorithm %s".formatted(
                            policy.policyId(), content.keyId(), policy.allowedAlgorithm())
            );
        }

        return PolicyValidationResult.allowed(policy);
    }

    public String resolvePreviousKeyId(String currentKeyId) {
        if (currentKeyId == null || currentKeyId.isBlank()) {
            return currentKeyId;
        }
        if (currentKeyId.endsWith("/current")) {
            return currentKeyId.substring(0, currentKeyId.length() - "/current".length()) + "/previous";
        }
        if (currentKeyId.endsWith("-current")) {
            return currentKeyId.substring(0, currentKeyId.length() - "-current".length()) + "-previous";
        }
        if (currentKeyId.endsWith(":current")) {
            return currentKeyId.substring(0, currentKeyId.length() - ":current".length()) + ":previous";
        }

        return currentKeyId + "/previous";
    }

    private boolean keyIdMatchesAlgorithm(String keyId, Algorithm algorithm) {
        if (keyId == null || keyId.isBlank()) {
            return false;
        }

        String expectedToken = switch (algorithm) {
            case HMAC_SHA256 -> "hmac";
            case RSA_PSS_SHA256 -> "rsa";
            case ECDSA_P256_SHA256 -> "ecdsa";
        };

        return keyId.toLowerCase(Locale.ROOT).contains(expectedToken);
    }
}

