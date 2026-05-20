package com.alexthesis.persistence.handler;

import com.alexthesis.persistence.service.PersistenceService;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PersistenceHandlerTest {

    @Mock
    PersistenceService persistenceService;

    private PersistenceHandler handler;

    @BeforeEach
    void setUp() {
        handler = new PersistenceHandler(persistenceService);
    }

    @Test
    void handleRequest_processesEveryRecord() {
        SQSEvent event = new SQSEvent();
        event.setRecords(List.of(message("m-1", "body-1"), message("m-2", "body-2")));

        handler.handleRequest(event, null);

        verify(persistenceService).processMessage("body-1");
        verify(persistenceService).processMessage("body-2");
        verifyNoMoreInteractions(persistenceService);
    }

    @Test
    void handleRequest_propagatesFailure() {
        SQSEvent event = new SQSEvent();
        event.setRecords(List.of(message("m-1", "body-1")));
        doThrow(new RuntimeException("DynamoDB unavailable")).when(persistenceService).processMessage("body-1");

        assertThatThrownBy(() -> handler.handleRequest(event, null))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("DynamoDB unavailable");
    }

    private static SQSEvent.SQSMessage message(String messageId, String body) {
        SQSEvent.SQSMessage message = new SQSEvent.SQSMessage();
        message.setMessageId(messageId);
        message.setBody(body);
        return message;
    }
}

