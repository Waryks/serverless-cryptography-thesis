package com.alexthesis.lambda;

import com.alexthesis.service.ConsumerService;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import jakarta.inject.Inject;

public class ConsumerHandler implements RequestHandler<SQSEvent, Void> {

    private final ConsumerService consumerService;

    @Inject
    public ConsumerHandler(ConsumerService consumerService) {
        this.consumerService = consumerService;
    }

    @Override
    public Void handleRequest(SQSEvent event, Context context) {
        for(SQSEvent.SQSMessage message : event.getRecords()) {
            consumerService.processMessage(message.getBody());
        }

        return null;
    }
}
