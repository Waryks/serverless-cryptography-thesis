package com.alexthesis.validation.checks;

import com.alexthesis.messaging.SignedContent;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Checks whether an event falls within the allowed replay protection window.
 *
 * <p>Replay checking is configurable:
 * - {@code thesis.security.replay-check-enabled} (default: true)
 * - {@code thesis.security.replay-window-ms} (default: 300000 ms = 5 minutes)
 *
 * <p>If replay checking is disabled, all events pass the replay check.
 *
 * <p>If replay checking is enabled, an event is considered replayed if:
 * {@code System.currentTimeMillis() - event.timestampEpochMs() > replayWindowMs}
 */
@ApplicationScoped
public class ReplayChecker {

    private final boolean enabled;
    private final long replayWindowMs;

    public ReplayChecker(
            @ConfigProperty(name = "thesis.security.replay-check-enabled", defaultValue = "true") boolean enabled,
            @ConfigProperty(name = "thesis.security.replay-window-ms", defaultValue = "300000") long replayWindowMs) {
        this.enabled = enabled;
        this.replayWindowMs = replayWindowMs;
    }

    /**
     * Checks whether the event is within the allowed replay window.
     *
     * @param content the signed content containing the timestamp
     * @return {@code true} if the event is within the allowed window, {@code false} if it is considered replayed
     */
    public boolean isWithinReplayWindow(SignedContent content) {
        return isWithinReplayWindow(content, replayWindowMs);
    }

    /**
     * Checks whether the event is within the supplied replay window.
     *
     * @param content the signed content containing the timestamp
     * @param windowMs replay window in milliseconds
     * @return {@code true} if the event is within the allowed window, {@code false} if it is considered replayed
     */
    public boolean isWithinReplayWindow(SignedContent content, long windowMs) {
        if (!enabled) {
            return true; // Replay checking disabled: all events pass
        }

        long now = System.currentTimeMillis();
        long age = now - content.timestampEpochMs();

        return age <= windowMs;
    }
}


