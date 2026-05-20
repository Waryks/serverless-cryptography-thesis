package com.alexthesis.validation.routing;

import com.alexthesis.messaging.Algorithm;
import com.alexthesis.messaging.AuditReason;
import com.alexthesis.messaging.RejectedEvent;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.GetQueueUrlRequest;
import software.amazon.awssdk.services.sqs.model.GetQueueUrlResponse;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ValidationRouterTest {

    private static final String ACCEPTED_QUEUE_NAME = "thesis-accepted-events";
    private static final String REJECTED_QUEUE_NAME = "thesis-rejected-events";
    private static final String ACCEPTED_QUEUE_URL = "https://sqs.local/accepted";
    private static final String REJECTED_QUEUE_URL = "https://sqs.local/rejected";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    SqsClient sqsClient;

    private ValidationRouter router;

    @BeforeEach
    void setUp() {
        router = new ValidationRouter(sqsClient, objectMapper, ACCEPTED_QUEUE_NAME, REJECTED_QUEUE_NAME);
    }

    @Test
    void routeAccepted_serializesEventAndCachesQueueUrl() throws Exception {
        SignedEvent event = signedEvent("evt-accepted");
        when(sqsClient.getQueueUrl(any(GetQueueUrlRequest.class)))
                .thenReturn(GetQueueUrlResponse.builder().queueUrl(ACCEPTED_QUEUE_URL).build());

        router.routeAccepted(event);
        router.routeAccepted(event);

        ArgumentCaptor<GetQueueUrlRequest> queueRequestCaptor = ArgumentCaptor.forClass(GetQueueUrlRequest.class);
        verify(sqsClient, times(1)).getQueueUrl(queueRequestCaptor.capture());
        assertEquals(ACCEPTED_QUEUE_NAME, queueRequestCaptor.getValue().queueName());

        ArgumentCaptor<SendMessageRequest> sendRequestCaptor = ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(sqsClient, times(2)).sendMessage(sendRequestCaptor.capture());
        assertEquals(ACCEPTED_QUEUE_URL, sendRequestCaptor.getAllValues().get(0).queueUrl());
        assertEquals(ACCEPTED_QUEUE_URL, sendRequestCaptor.getAllValues().get(1).queueUrl());
        assertEquals(objectMapper.writeValueAsString(event), sendRequestCaptor.getAllValues().get(0).messageBody());
        assertEquals(objectMapper.writeValueAsString(event), sendRequestCaptor.getAllValues().get(1).messageBody());
    }

    @Test
    void routeRejected_serializesRejectedEventWithOriginalEventAndReason() throws Exception {
        SignedEvent originalEvent = signedEvent("evt-rejected");
        when(sqsClient.getQueueUrl(any(GetQueueUrlRequest.class)))
                .thenReturn(GetQueueUrlResponse.builder().queueUrl(REJECTED_QUEUE_URL).build());

        long before = System.currentTimeMillis();
        router.routeRejected(originalEvent, AuditReason.INVALID_SIGNATURE, "signature mismatch");
        long after = System.currentTimeMillis();

        ArgumentCaptor<GetQueueUrlRequest> queueRequestCaptor = ArgumentCaptor.forClass(GetQueueUrlRequest.class);
        verify(sqsClient).getQueueUrl(queueRequestCaptor.capture());
        assertEquals(REJECTED_QUEUE_NAME, queueRequestCaptor.getValue().queueName());

        ArgumentCaptor<SendMessageRequest> sendRequestCaptor = ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(sqsClient).sendMessage(sendRequestCaptor.capture());
        assertEquals(REJECTED_QUEUE_URL, sendRequestCaptor.getValue().queueUrl());

        RejectedEvent rejectedEvent = objectMapper.readValue(sendRequestCaptor.getValue().messageBody(), RejectedEvent.class);
        assertEquals(originalEvent, rejectedEvent.originalEvent());
        assertEquals(AuditReason.INVALID_SIGNATURE, rejectedEvent.reason());
        assertEquals("signature mismatch", rejectedEvent.message());
        assertTrue(rejectedEvent.rejectedAtEpochMs() >= before && rejectedEvent.rejectedAtEpochMs() <= after);
    }

    private SignedEvent signedEvent(String eventId) {
        ObjectNode payload = objectMapper.createObjectNode().put("data", "test");
        SignedContent content = new SignedContent(
                eventId,
                System.currentTimeMillis(),
                Algorithm.HMAC_SHA256,
                "key-1",
                payload
        );
        return new SignedEvent(content, "signature-b64");
    }
}

