package com.alexthesis.audit.mapping;

import com.alexthesis.audit.model.AuditRecord;
import com.alexthesis.messaging.AuditReason;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.RejectedEvent;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AuditMapperTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void toAuditRecord_mapsAllFields() throws Exception {
        JsonNode payload = objectMapper.readTree("{\"foo\":\"bar\"}");

        SignedContent content = new SignedContent("evt-1", 1610000000000L, Algorithm.HMAC_SHA256, "key-1", payload);
        SignedEvent signedEvent = new SignedEvent(content, "signature-b64");

        RejectedEvent rejectedEvent = new RejectedEvent(signedEvent, AuditReason.INVALID_SIGNATURE, "bad signature", 1610000001000L);

        AuditMapper mapper = new AuditMapper();
        AuditRecord record = mapper.toAuditRecord(rejectedEvent);

        assertThat(record).isNotNull();
        assertThat(record.auditId()).isNotNull();
        assertThat(record.eventId()).isEqualTo("evt-1");
        assertThat(record.reason()).isEqualTo("INVALID_SIGNATURE");
        assertThat(record.message()).isEqualTo("bad signature");
        assertThat(record.algorithm()).isEqualTo("HMAC_SHA256");
        assertThat(record.keyId()).isEqualTo("key-1");
        assertThat(record.payload()).contains("\"foo\":\"bar\"");
        assertThat(record.signatureB64()).isEqualTo("signature-b64");
        assertThat(record.rejectedAtEpochMs()).isEqualTo(1610000001000L);
        assertThat(record.persistedAtEpochMs()).isNotZero();
    }
}

