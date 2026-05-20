package com.alexthesis.validation.policy;

import com.alexthesis.messaging.AuditReason;

/**
 * Result of evaluating a policy against an event.
 */
public record PolicyValidationResult(
        SecurityPolicy policy,
        boolean allowed,
        AuditReason rejectionReason,
        String rejectionMessage
) {
    public static PolicyValidationResult allowed(SecurityPolicy policy) {
        return new PolicyValidationResult(policy, true, null, null);
    }

    public static PolicyValidationResult rejected(SecurityPolicy policy, AuditReason reason, String message) {
        return new PolicyValidationResult(policy, false, reason, message);
    }
}

