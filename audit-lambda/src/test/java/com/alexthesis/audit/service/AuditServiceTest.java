package com.alexthesis.audit.service;

import com.alexthesis.audit.mapping.AuditMapper;
import com.alexthesis.audit.model.AuditRecord;
import com.alexthesis.audit.repository.AuditRepository;
import com.alexthesis.messaging.AuditReason;
import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.RejectedEvent;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuditServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void processMessage_deserializesAndSaves() throws Exception {
        // prepare a RejectedEvent JSON
        JsonNode payload = objectMapper.readTree("{\"x\":1}");
        SignedContent content = new SignedContent("evt-xyz", 1620000000000L, Algorithm.HMAC_SHA256, "key-abc", payload);
        SignedEvent signedEvent = new SignedEvent(content, "sig-b64");
        RejectedEvent rejectedEvent = new RejectedEvent(signedEvent, AuditReason.DESERIALIZATION_ERROR, "oops", 1620000001000L);

        String json = objectMapper.writeValueAsString(rejectedEvent);

        // mocks
        AuditMapper mapper = mock(AuditMapper.class);
        AuditRepository repository = mock(AuditRepository.class);

        AuditRecord fakeRecord = new AuditRecord("aid-1", "evt-xyz", "DESERIALIZATION_ERROR", "oops", "HMAC_SHA256", "key-abc", "{\"x\":1}", "sig-b64", 1620000001000L, 1620000002000L);
        when(mapper.toAuditRecord(any())).thenReturn(fakeRecord);

        AuditService service = new AuditService(objectMapper, mapper, repository);

        service.processMessage(json);

        verify(repository).save(fakeRecord);
    }
}

