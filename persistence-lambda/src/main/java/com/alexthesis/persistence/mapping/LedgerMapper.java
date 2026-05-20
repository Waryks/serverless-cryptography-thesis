package com.alexthesis.persistence.mapping;

import com.alexthesis.messaging.SignedEvent;
import com.alexthesis.persistence.model.LedgerRecord;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.Objects;

@ApplicationScoped
public class LedgerMapper {

    public LedgerRecord toLedgerRecord(SignedEvent event) {
        return toLedgerRecord(event, System.currentTimeMillis());
    }

    LedgerRecord toLedgerRecord(SignedEvent event, long persistedAtEpochMs) {
        Objects.requireNonNull(event, "event must not be null");
        Objects.requireNonNull(event.content(), "event.content must not be null");

        return new LedgerRecord(
                event.content().eventId(),
                event.content().algorithm().name(),
                event.content().keyId(),
                event.content().payload().toString(),
                event.signatureB64(),
                event.content().timestampEpochMs(),
                persistedAtEpochMs
        );
    }
}

