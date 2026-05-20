package com.alexthesis.validation.service;

import com.alexthesis.messaging.AuditReason;
import com.alexthesis.messaging.SignedEvent;

/**
 * Represents a validation decision made by the validation service.
 *
 * <p>Each decision encapsulates whether the event was accepted or rejected,
 * along with rejection reason and message if applicable.
 */
public sealed class ValidationDecision permits ValidationDecision.Accepted, ValidationDecision.Rejected {

    /**
     * Factory method for creating an accepted decision.
     *
     * @param event the SignedEvent that was accepted
     * @return an Accepted decision
     */
    public static Accepted accepted(SignedEvent event) {
        return new Accepted(event);
    }

    /**
     * Factory method for creating a rejected decision.
     *
     * @param event  the original SignedEvent (may be null if deserialization failed)
     * @param reason the reason for rejection
     * @param message descriptive message about the rejection
     * @return a Rejected decision
     */
    public static Rejected rejected(SignedEvent event, AuditReason reason, String message) {
        return new Rejected(event, reason, message);
    }

    /**
     * Represents an accepted event: validation passed all checks.
     */
    public static final class Accepted extends ValidationDecision {
        private final SignedEvent event;

        public Accepted(SignedEvent event) {
            this.event = event;
        }

        public SignedEvent event() {
            return event;
        }
    }

    /**
     * Represents a rejected event: validation failed one or more checks.
     */
    public static final class Rejected extends ValidationDecision {
        private final SignedEvent originalEvent;
        private final AuditReason reason;
        private final String message;

        public Rejected(SignedEvent originalEvent, AuditReason reason, String message) {
            this.originalEvent = originalEvent;
            this.reason = reason;
            this.message = message;
        }

        public SignedEvent originalEvent() {
            return originalEvent;
        }

        public AuditReason reason() {
            return reason;
        }

        public String message() {
            return message;
        }
    }
}


