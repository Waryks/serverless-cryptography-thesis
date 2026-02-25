package com.alexthesis.lambda;

public record ProducerResponse(
        String eventId,
        boolean coldStart,
        double durationMs
) {}
