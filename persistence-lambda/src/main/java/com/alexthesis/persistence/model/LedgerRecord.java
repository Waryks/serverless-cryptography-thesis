package com.alexthesis.persistence.model;

public record LedgerRecord(
        String eventId,
        String algorithm,
        String keyId,
        String payload,
        String signatureB64,
        long acceptedAtEpochMs,
        long persistedAtEpochMs
) {}

