package com.alexthesis.messaging;

public enum AuditReason {
    INVALID_SIGNATURE,
    EXPIRED,
    REPLAY_DETECTED,
    UNKNOWN_KEY,
    ALGORITHM_MISMATCH,
    POLICY_REJECTED,
    DESERIALIZATION_ERROR,
    INTERNAL_ERROR
}

