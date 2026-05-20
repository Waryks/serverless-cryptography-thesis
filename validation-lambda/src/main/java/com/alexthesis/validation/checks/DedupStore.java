package com.alexthesis.validation.checks;

import com.alexthesis.messaging.SignedContent;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * Placeholder for deduplication checking using DynamoDB.
 *
 * <p>Deduplication ensures that an event with the same {@code eventId} is not processed twice.
 * This protects against:
 * - SQS at-least-once delivery duplicates
 * - Replay attacks (if an old but fresh-looking event is resubmitted)
 * - Intentional duplicate submissions
 *
 * <p>Deduplication is configurable via {@code thesis.security.dedup-enabled} (default: true).
 *
 * <p><strong>Current implementation is a placeholder.</strong>
 * Final implementation will:
 * - Check whether eventId already exists in DynamoDB thesis_dedup table
 * - If it exists, reject as duplicate
 * - If it does not exist, mark it as seen (with TTL)
 *
 * <p>For now, all events pass the dedup check.
 */
@ApplicationScoped
public class DedupStore {

    private static final Logger log = Logger.getLogger(DedupStore.class);

    private final boolean enabled;

    public DedupStore(
            @ConfigProperty(name = "thesis.security.dedup-enabled", defaultValue = "true") boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Checks whether an event has been seen before and marks it as seen if it is new.
     *
     * <p><strong>TODO:</strong> Implement DynamoDB interaction:
     * - Query thesis_dedup table for eventId
     * - If found, return false (duplicate)
     * - If not found, write new dedup entry with TTL and return true (new)
     * - Handle transactional writes with ledger table in the final version
     *
     * @param content the signed content containing the eventId
     * @return {@code true} if the event is new (not a duplicate), {@code false} if it is a duplicate
     */
    public boolean isNewEvent(SignedContent content) {
        if (!enabled) {
            return true; // Dedup checking disabled: all events are considered new
        }

        // TODO: Implement DynamoDB dedup check
        log.debugf("TODO: Dedup check for eventId=%s (currently passing)", content.eventId());
        return true;
    }
}


