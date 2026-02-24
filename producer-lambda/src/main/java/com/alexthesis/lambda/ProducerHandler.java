package com.alexthesis.lambda;

import com.alexthesis.messaging.SignedEvent;
import com.alexthesis.service.ProducerService;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import jakarta.inject.Inject;

public class ProducerHandler implements RequestHandler<SignedEvent, ProducerResponse> {

    private final ProducerService producerService;

    @Inject
    public ProducerHandler(ProducerService producerService) {
        this.producerService = producerService;
    }

    @Override
    public ProducerResponse handleRequest(SignedEvent signedEvent, Context context) {
        return producerService.processEvent(signedEvent);
    }
}

