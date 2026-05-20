package com.alexthesis.audit.mapping;

import com.alexthesis.audit.model.AuditRecord;
import com.alexthesis.messaging.RejectedEvent;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.Objects;
import java.util.UUID;

@ApplicationScoped
public class AuditMapper {

    public AuditRecord toAuditRecord(RejectedEvent rejectedEvent) {
        Objects.requireNonNull(rejectedEvent, "rejectedEvent must not be null");

        long persistedAt = System.currentTimeMillis();
        String auditId = UUID.randomUUID().toString();

        String eventId = null;
        String algorithm = null;
        String keyId = null;
        String payload = null;
        String signatureB64 = null;
        long rejectedAt = rejectedEvent.rejectedAtEpochMs();

        if (rejectedEvent.originalEvent() != null) {
            if (rejectedEvent.originalEvent().content() != null) {
                eventId = rejectedEvent.originalEvent().content().eventId();
                algorithm = rejectedEvent.originalEvent().content().algorithm() != null ? rejectedEvent.originalEvent().content().algorithm().name() : null;
                keyId = rejectedEvent.originalEvent().content().keyId();
                payload = rejectedEvent.originalEvent().content().payload() != null ? rejectedEvent.originalEvent().content().payload().toString() : null;
            }
            signatureB64 = rejectedEvent.originalEvent().signatureB64();
        }

        return new AuditRecord(
                auditId,
                eventId,
                rejectedEvent.reason() != null ? rejectedEvent.reason().name() : null,
                rejectedEvent.message(),
                algorithm,
                keyId,
                payload,
                signatureB64,
                rejectedAt,
                persistedAt
        );
    }
}

