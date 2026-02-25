package com.alexthesis.lambda;

import com.alexthesis.crypto.KeySecret;
import com.alexthesis.crypto.SecretService;
import com.alexthesis.crypto.VerificationService;
import com.alexthesis.dynamo.DedupRepository;
import com.alexthesis.dynamo.LedgerRepository;
import com.alexthesis.messaging.SignedContent;
import com.alexthesis.messaging.SignedEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;

/**
 * Core business logic for the consumer Lambda.
 * Deserialises each SQS message, verifies its cryptographic signature,
 * enforces the replay-protection window, and delegates to persistence.
 */
@ApplicationScoped
public class ConsumerService {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Logger log = Logger.getLogger(ConsumerService.class);

    private final SecretService secretService;
    private final VerificationService verificationService;
    private final DedupRepository dedupRepository;
    private final LedgerRepository ledgerRepository;
    private final DynamoDbClient dynamoDbClient;
    private final boolean replayCheckEnabled;
    private final long replayWindowMs;

    @Inject
    public ConsumerService(SecretService secretService,
                           VerificationService verificationService,
                           DedupRepository dedupRepository,
                           LedgerRepository ledgerRepository,
                           DynamoDbClient dynamoDbClient,
                           @ConfigProperty(name = "thesis.replay-check.enabled", defaultValue = "true") boolean replayCheckEnabled,
                           @ConfigProperty(name = "thesis.replay-check.window-ms", defaultValue = "300000") long replayWindowMs) {
        this.secretService = secretService;
        this.verificationService = verificationService;
        this.dedupRepository = dedupRepository;
        this.ledgerRepository = ledgerRepository;
        this.dynamoDbClient = dynamoDbClient;
        this.replayCheckEnabled = replayCheckEnabled;
        this.replayWindowMs = replayWindowMs;
    }

    /**
     * Processes a single SQS message body:
     * <ol>
     *   <li>Deserialises the JSON into a {@link SignedEvent}</li>
     *   <li>Loads the key from Secrets Manager using {@link SignedContent#keyId()}</li>
     *   <li>Recreates canonical bytes and verifies the signature</li>
     *   <li>Rejects the message if the signature is invalid</li>
     *   <li>Enforces the replay-protection timestamp window</li>
     * </ol>
     *
     * @param messageBodyJson raw SQS message body
     * @throws RuntimeException if processing fails for any reason
     */
    public void processMessage(String messageBodyJson) {
        SignedEvent event = readEventValue(messageBodyJson);
        SignedContent content = event.content();

        KeySecret secret = secretService.getSecret(content.keyId());

        if (!verificationService.verifySignature(content, event.signatureB64(), secret)) {
            throw new InvalidSignatureException("Invalid signature for eventId: " + content.eventId());
        }

        processWindow(content);
        persistToLedgerAndDedup(content);

        log.infof("Processed eventId=%s algorithm=%s", content.eventId(), content.algorithm());
    }

    private SignedEvent readEventValue(String messageBodyJson) {
        try {
            return MAPPER.readValue(messageBodyJson, SignedEvent.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to process SQS message", e);
        }
    }

    /**
     * Validates that the event timestamp falls within the allowed replay window.
     * Skipped entirely when {@code thesis.replay-check.enabled=false}.
     *
     * @throws ReplayWindowException if the event is older than {@code thesis.replay-check.window-ms}
     */
    private void processWindow(SignedContent content) {
        if (!replayCheckEnabled) {
            return;
        }

        long age = System.currentTimeMillis() - content.timestampEpochMs();
        if (age > replayWindowMs) {
            throw new ReplayWindowException("Replay window exceeded. Event age: " + age + "ms");
        }
    }
    
    private void persistToLedgerAndDedup(SignedContent content) {
        try {
            dynamoDbClient.transactWriteItems(TransactWriteItemsRequest.builder()
                    .transactItems(
                            ledgerRepository.buildTransactItem(content),
                            dedupRepository.buildTransactItem(content)
                    )
                    .build());
        } catch (TransactionCanceledException e) {
            throw new DuplicateEventException("Duplicate eventId detected: " + content.eventId(), e);
        }
    }

    /** Thrown when signature verification fails. */
    public static class InvalidSignatureException extends RuntimeException {
        public InvalidSignatureException(String message) {
            super(message);
        }
    }

    /** Thrown when an event arrives outside the allowed timestamp window. */
    public static class ReplayWindowException extends RuntimeException {
        public ReplayWindowException(String message) {
            super(message);
        }
    }

    /** Thrown when the dedup+ledger transaction is cancelled due to a duplicate eventId. */
    public static class DuplicateEventException extends RuntimeException {
        public DuplicateEventException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
