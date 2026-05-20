package com.alexthesis.validation.checks;

import com.alexthesis.messaging.SignedContent;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.HashMap;
import java.util.Map;

/**
 * Persistence model for the deduplication table.
 *
 * <p>The model keeps the minimum set of fields needed to identify processed events and to
 * support future audit/debugging use cases.
 */
public final class ProcessedEventRecord {

    private final String eventId;
    private final long processedAtEpochMs;
    private final String algorithm;
    private final String keyId;
    private final long ttlEpochSeconds;

    private ProcessedEventRecord(String eventId, long processedAtEpochMs, String algorithm, String keyId, long ttlEpochSeconds) {
        this.eventId = eventId;
        this.processedAtEpochMs = processedAtEpochMs;
        this.algorithm = algorithm;
        this.keyId = keyId;
        this.ttlEpochSeconds = ttlEpochSeconds;
    }

    public static ProcessedEventRecord from(SignedContent content, long dedupTtlSeconds) {
        long processedAtEpochMs = System.currentTimeMillis();
        long ttlEpochSeconds = (processedAtEpochMs / 1000L) + dedupTtlSeconds;
        return new ProcessedEventRecord(
                content.eventId(),
                processedAtEpochMs,
                content.algorithm().name(),
                content.keyId(),
                ttlEpochSeconds
        );
    }

    public String eventId() {
        return eventId;
    }

    public long processedAtEpochMs() {
        return processedAtEpochMs;
    }

    public String algorithm() {
        return algorithm;
    }

    public String keyId() {
        return keyId;
    }

    public long ttlEpochSeconds() {
        return ttlEpochSeconds;
    }

    public Map<String, AttributeValue> toItem() {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("eventId", AttributeValue.fromS(eventId));
        item.put("processedAtEpochMs", AttributeValue.fromN(Long.toString(processedAtEpochMs)));
        item.put("algorithm", AttributeValue.fromS(algorithm));
        item.put("keyId", AttributeValue.fromS(keyId));
        item.put("ttl", AttributeValue.fromN(Long.toString(ttlEpochSeconds)));
        return item;
    }
}


