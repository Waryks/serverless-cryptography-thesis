package com.alexthesis.validation.policy;

import com.alexthesis.messaging.SignedContent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;

/**
 * Resolves which policy applies to a given event.
 *
 * <p>Current strategy:
 * <ul>
 *   <li>look for an algorithm-specific mapping under {@code thesis.policy.algorithm.&lt;ALGO&gt;}</li>
 *   <li>otherwise fall back to {@code thesis.policy.default}</li>
 * </ul>
 */
@ApplicationScoped
public class PolicyResolver {

    private final Config config;
    private final PolicyLoader policyLoader;

    @Inject
    public PolicyResolver(Config config, PolicyLoader policyLoader) {
        this.config = config;
        this.policyLoader = policyLoader;
    }

    public SecurityPolicy resolve(SignedContent content) {
        String policyId = config.getOptionalValue(
                "thesis.policy.algorithm." + content.algorithm().name(),
                String.class
        ).orElseGet(() -> config.getOptionalValue("thesis.policy.default", String.class)
                .orElseThrow(() -> new IllegalStateException("Missing policy configuration: thesis.policy.default")));

        return policyLoader.loadPolicy(policyId);
    }
}

