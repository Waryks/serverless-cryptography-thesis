package com.alexthesis.persistence.mapping;

import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.alexthesis.persistence.model.LedgerRecord;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LedgerMapperTest {

    private final LedgerMapper ledgerMapper = new LedgerMapper();

    @Test
    void toLedgerRecord_mapsAllFields() {
        SignedEvent event = buildEvent();

        LedgerRecord record = ledgerMapper.toLedgerRecord(event, 1_700_000_000_123L);

        assertThat(record.eventId()).isEqualTo("evt-1");
        assertThat(record.algorithm()).isEqualTo(Algorithm.HMAC_SHA256.name());
        assertThat(record.keyId()).isEqualTo("key-1");
        assertThat(record.payload()).isEqualTo("{\"amount\":100}");
        assertThat(record.signatureB64()).isEqualTo("sig-1");
        assertThat(record.acceptedAtEpochMs()).isEqualTo(1_700_000_000_000L);
        assertThat(record.persistedAtEpochMs()).isEqualTo(1_700_000_000_123L);
    }

    private static SignedEvent buildEvent() {
        SignedContent content = new SignedContent(
                "evt-1",
                1_700_000_000_000L,
                Algorithm.HMAC_SHA256,
                "key-1",
                JsonNodeFactory.instance.objectNode().put("amount", 100)
        );
        return new SignedEvent(content, "sig-1");
    }
}

