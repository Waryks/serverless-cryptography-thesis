package com.alexthesis.persistence.service;

import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.alexthesis.persistence.mapping.LedgerMapper;
import com.alexthesis.persistence.model.LedgerRecord;
import com.alexthesis.persistence.repository.LedgerRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

@ApplicationScoped
public class PersistenceService {

    private static final Logger log = Logger.getLogger(PersistenceService.class);

    private final ObjectMapper objectMapper;
    private final LedgerMapper ledgerMapper;
    private final LedgerRepository ledgerRepository;

    @Inject
    public PersistenceService(ObjectMapper objectMapper,
                              LedgerMapper ledgerMapper,
                              LedgerRepository ledgerRepository) {
        this.objectMapper = objectMapper;
        this.ledgerMapper = ledgerMapper;
        this.ledgerRepository = ledgerRepository;
    }

    public void processMessage(String messageBodyJson) {
        SignedEvent event = deserializeEvent(messageBodyJson);
        validateStructure(event);

        LedgerRecord record = ledgerMapper.toLedgerRecord(event);
        ledgerRepository.save(record);
        log.infof("eventId=%s persisted=true", record.eventId());
    }

    private SignedEvent deserializeEvent(String messageBodyJson) {
        try {
            return objectMapper.readValue(messageBodyJson, SignedEvent.class);
        } catch (Exception e) {
            log.errorf(e, "Failed to deserialize accepted event");
            throw new RuntimeException("Failed to deserialize accepted event", e);
        }
    }

    private void validateStructure(SignedEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("Missing event");
        }
        if (event.content() == null) {
            throw new IllegalArgumentException("Missing event content");
        }

        SignedContent content = event.content();
        if (content.eventId() == null || content.eventId().isBlank()) {
            throw new IllegalArgumentException("Missing or empty eventId");
        }
        if (content.algorithm() == null) {
            throw new IllegalArgumentException("Missing algorithm");
        }
        if (content.keyId() == null || content.keyId().isBlank()) {
            throw new IllegalArgumentException("Missing or empty keyId");
        }
        if (content.payload() == null) {
            throw new IllegalArgumentException("Missing payload");
        }
        if (event.signatureB64() == null || event.signatureB64().isBlank()) {
            throw new IllegalArgumentException("Missing signature");
        }
    }
}

