package com.alexthesis.persistence.service;

import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.alexthesis.persistence.mapping.LedgerMapper;
import com.alexthesis.persistence.model.LedgerRecord;
import com.alexthesis.persistence.repository.LedgerRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PersistenceServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    LedgerMapper ledgerMapper;

    @Mock
    LedgerRepository ledgerRepository;

    private PersistenceService persistenceService;

    @BeforeEach
    void setUp() {
        persistenceService = new PersistenceService(objectMapper, ledgerMapper, ledgerRepository);
    }

    @Test
    void processMessage_validEvent_persistsLedgerRecord() throws Exception {
        SignedEvent event = buildEvent();
        LedgerRecord record = new LedgerRecord(
                "evt-1",
                "HMAC_SHA256",
                "key-1",
                "{\"amount\":100}",
                "sig-1",
                1_700_000_000_000L,
                1_700_000_000_123L
        );
        when(ledgerMapper.toLedgerRecord(any(SignedEvent.class))).thenReturn(record);

        persistenceService.processMessage(objectMapper.writeValueAsString(event));

        verify(ledgerRepository).save(record);
    }

    @Test
    void processMessage_invalidJson_throwsRuntimeException() {
        assertThatThrownBy(() -> persistenceService.processMessage("{invalid json}"))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to deserialize accepted event");
        verifyNoInteractions(ledgerMapper, ledgerRepository);
    }

    @Test
    void processMessage_missingSignature_throwsIllegalArgumentException() throws Exception {
        SignedEvent event = new SignedEvent(buildContent(), "");

        assertThatThrownBy(() -> persistenceService.processMessage(objectMapper.writeValueAsString(event)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Missing signature");
        verifyNoInteractions(ledgerMapper, ledgerRepository);
    }

    private static SignedEvent buildEvent() {
        return new SignedEvent(buildContent(), "sig-1");
    }

    private static SignedContent buildContent() {
        return new SignedContent(
                "evt-1",
                1_700_000_000_000L,
                Algorithm.HMAC_SHA256,
                "key-1",
                JsonNodeFactory.instance.objectNode().put("amount", 100)
        );
    }
}

