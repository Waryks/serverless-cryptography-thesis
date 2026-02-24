package com.alexthesis.messaging;

public record SignedEvent(
        SignedContent content,
        String signatureB64
) {}
