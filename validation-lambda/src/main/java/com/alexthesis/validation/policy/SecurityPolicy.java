package com.alexthesis.validation.policy;

import com.alexthesis.messaging.Algorithm;

/**
 * Immutable validation policy describing how a signed event should be checked.
 */
public record SecurityPolicy(
        String policyId,
        Algorithm allowedAlgorithm,
        boolean replayCheckEnabled,
        long replayWindowMs,
        boolean dedupEnabled,
        boolean allowPreviousKey,
        boolean strictValidation
) {
}

