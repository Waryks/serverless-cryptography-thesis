package com.alexthesis.metrics;

/**
 * Named timing stages used across lambdas for instrumentation.
 */
public enum TimingStage {
    // Producer stages
    PRODUCER_TOTAL,
    KEY_LOADING,
    KEY_PARSING,
    CONTENT_SERIALIZATION,
    SIGNING,
    SQS_PUBLISH,

    // Validation stages
    VALIDATION_TOTAL,
    POLICY_LOADING,
    REPLAY_CHECK,
    DEDUP_CHECK,
    SIGNATURE_VERIFICATION,
    ROUTING,
    ACCEPTED_PUBLISH,
    REJECTED_PUBLISH,

    // Persistence stages
    PERSISTENCE_TOTAL,
    LEDGER_MAPPING,
    LEDGER_WRITE,

    // Audit stages
    AUDIT_TOTAL,
    AUDIT_MAPPING,
    AUDIT_WRITE,

    // Generic handler stage
    LAMBDA_HANDLER
}

