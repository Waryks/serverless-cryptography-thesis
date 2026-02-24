package com.alexthesis.messaging;

import com.fasterxml.jackson.databind.JsonNode;

public record SignedContent(
        String eventId,
        long timestampEpochMs,
        Algorithm algorithm,
        String keyId,
        JsonNode payload
) {}
