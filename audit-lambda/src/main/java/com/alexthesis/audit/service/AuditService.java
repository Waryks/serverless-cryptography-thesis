package com.alexthesis.audit.service;

import com.alexthesis.audit.mapping.AuditMapper;
import com.alexthesis.audit.model.AuditRecord;
import com.alexthesis.audit.repository.AuditRepository;
import com.alexthesis.messaging.RejectedEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.alexthesis.metrics.ColdStartTracker;
import com.alexthesis.metrics.MetricsContext;
import com.alexthesis.metrics.TimingStage;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

@ApplicationScoped
public class AuditService {

    private static final Logger log = Logger.getLogger(AuditService.class);

    private final ObjectMapper objectMapper;
    private final AuditMapper auditMapper;
    private final AuditRepository auditRepository;

    @Inject
    public AuditService(ObjectMapper objectMapper,
                        AuditMapper auditMapper,
                        AuditRepository auditRepository) {
        this.objectMapper = objectMapper;
        this.auditMapper = auditMapper;
        this.auditRepository = auditRepository;
    }

    public void processMessage(String messageBodyJson) {
        RejectedEvent rejectedEvent = deserializeRejectedEvent(messageBodyJson);

        String eventId = rejectedEvent.originalEvent() != null && rejectedEvent.originalEvent().content() != null
                ? rejectedEvent.originalEvent().content().eventId()
                : "unknown";

        boolean isColdStart = ColdStartTracker.isColdStartAndMark("audit");
        try (MetricsContext ctx = MetricsContext.create("audit", eventId, isColdStart)) {
            ctx.start(TimingStage.LAMBDA_HANDLER);

            ctx.start(TimingStage.AUDIT_MAPPING);
            AuditRecord record = auditMapper.toAuditRecord(rejectedEvent);
            ctx.stop(TimingStage.AUDIT_MAPPING);

            ctx.start(TimingStage.AUDIT_WRITE);
            auditRepository.save(record);
            ctx.stop(TimingStage.AUDIT_WRITE);

            ctx.stop(TimingStage.LAMBDA_HANDLER);
            ctx.snapshot().ifPresent(s -> System.out.println(s.toJson()));

            log.infof("eventId=%s auditPersisted=true reason=%s", record.eventId(), record.reason());
        }
    }

    private RejectedEvent deserializeRejectedEvent(String json) {
        try {
            return objectMapper.readValue(json, RejectedEvent.class);
        } catch (Exception e) {
            log.errorf(e, "Failed to deserialize rejected event");
            throw new RuntimeException("Failed to deserialize rejected event", e);
        }
    }
}

