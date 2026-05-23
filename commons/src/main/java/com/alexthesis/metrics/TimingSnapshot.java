package com.alexthesis.metrics;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Immutable snapshot produced at the end of an invocation containing per-stage durations.
 */
public class TimingSnapshot {
    private final String eventId;
    private final String serviceName;
    private final boolean coldStart;
    private final Map<String, Double> durationsMs;
    private final long startEpochMs;
    private final long endEpochMs;

    public TimingSnapshot(String eventId, String serviceName, boolean coldStart, Map<String, Double> durationsMs, long startEpochMs, long endEpochMs) {
        this.eventId = eventId;
        this.serviceName = serviceName;
        this.coldStart = coldStart;
        this.durationsMs = Collections.unmodifiableMap(new HashMap<>(durationsMs));
        this.startEpochMs = startEpochMs;
        this.endEpochMs = endEpochMs;
    }

    public String getEventId() {
        return eventId;
    }

    public String getServiceName() {
        return serviceName;
    }

    public boolean isColdStart() {
        return coldStart;
    }

    public Map<String, Double> getDurationsMs() {
        return durationsMs;
    }

    public long getStartEpochMs() {
        return startEpochMs;
    }

    public long getEndEpochMs() {
        return endEpochMs;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new HashMap<>();
        m.put("eventId", eventId);
        m.put("service", serviceName);
        m.put("coldStart", coldStart);
        m.put("durations", durationsMs);
        m.put("startMs", startEpochMs);
        m.put("endMs", endEpochMs);
        return m;
    }

    public String toJson() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            Map<String, Object> m = toMap();
            return mapper.writeValueAsString(m);
        } catch (JsonProcessingException e) {
            // Fall back to a simple representation
            return String.format("{\"eventId\":\"%s\",\"service\":\"%s\"}", eventId, serviceName);
        }
    }
}

