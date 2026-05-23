package com.alexthesis.metrics;

import java.util.Optional;

/**
 * Lightweight per-invocation context used by application code to record stages.
 */
public class MetricsContext implements AutoCloseable {
    private final String eventId;
    private final String serviceName;
    private final boolean coldStart;

    private final TimingCollector collector = TimingCollector.get();

    private MetricsContext(String serviceName, String eventId, boolean coldStart) {
        this.serviceName = serviceName;
        this.eventId = eventId;
        this.coldStart = coldStart;
    }

    public static MetricsContext create(String serviceName, String eventId, boolean coldStart) {
        return new MetricsContext(serviceName, eventId, coldStart);
    }

    public void start(TimingStage stage) {
        collector.start(eventId, stage);
    }

    public void stop(TimingStage stage) {
        collector.stop(eventId, stage);
    }

    public Optional<TimingSnapshot> snapshot() {
        return collector.snapshot(eventId, serviceName, coldStart);
    }

    @Override
    public void close() {
        // Don't aggressively remove snapshot; leave it for callers to decide
        // but we remove the collector context to avoid memory leak.
        collector.remove(eventId);
    }
}

