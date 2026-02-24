package com.alexthesis.events;

import com.alexthesis.messaging.SignedEvent;

public interface EventPublisher {
    void publish(SignedEvent event);
}
