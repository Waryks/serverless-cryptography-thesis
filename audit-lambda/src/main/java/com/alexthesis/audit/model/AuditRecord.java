package com.alexthesis.audit.model;

public record AuditRecord(
        String auditId,
        String eventId,
        String reason,
        String message,
        String algorithm,
        String keyId,
        String payload,
        String signatureB64,
        long rejectedAtEpochMs,
        long persistedAtEpochMs
) {}

