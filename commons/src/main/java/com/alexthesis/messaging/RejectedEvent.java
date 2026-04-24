package com.alexthesis.messaging;

public record RejectedEvent(
        SignedEvent originalEvent,
        AuditReason reason,
        String message,
        long rejectedAtEpochMs
) {}

