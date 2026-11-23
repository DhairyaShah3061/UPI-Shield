package com.upishield.riskengine.rules;

import com.upishield.intelligence.dto.ThreatIndicatorDto;
import com.upishield.intelligence.service.ReputationService;
import com.upishield.riskengine.dto.RiskIndicator;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class MaliciousDomainRule implements RiskRule {

    public static final String RULE_ID = "RULE_MALICIOUS_DOMAIN";
    private static final int POINTS = 50;
    private static final String SEVERITY = "STRONG";

    private final ReputationService reputationService;

    public MaliciousDomainRule(ReputationService reputationService) {
        this.reputationService = reputationService;
    }

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public RiskIndicator evaluate(RiskContext context) {
        if (context == null) {
            return null;
        }

        boolean triggered = false;
        StringBuilder evidence = new StringBuilder();

        // 1. Check URL analyzer response
        if (context.urlAnalysis() != null) {
            if (context.urlAnalysis().isMalicious() || context.urlAnalysis().isPhishing() || context.urlAnalysis().isSuspiciousDomain()) {
                triggered = true;
                evidence.append("URL analysis flagged link as malicious/phishing (Score: ")
                        .append(context.urlAnalysis().getThreatScore()).append("). ");
                if (context.urlAnalysis().getThreatDescription() != null) {
                    evidence.append(context.urlAnalysis().getThreatDescription()).append(" ");
                }
            } else if (context.urlAnalysis().getDomain() != null) {
                // Check domain via reputation service
                Optional<ThreatIndicatorDto> threat = reputationService.lookupDomain(context.urlAnalysis().getDomain());
                if (threat.isPresent() && threat.get().isVerified()) {
                    triggered = true;
                    evidence.append("Domain (").append(context.urlAnalysis().getDomain())
                            .append(") matches a verified malicious indicator in threat intelligence database. ");
                }
            }
        }

        // 2. Check extracted URLs from message analysis
        if (!triggered && context.messageAnalysis() != null && context.messageAnalysis().getExtractedUrls() != null) {
            for (String extractedUrl : context.messageAnalysis().getExtractedUrls()) {
                String domain = extractDomain(extractedUrl);
                Optional<ThreatIndicatorDto> threat = reputationService.lookupDomain(domain);
                if (threat.isPresent() && threat.get().isVerified()) {
                    triggered = true;
                    evidence.append("Message contains URL matching verified phishing domain: ").append(domain).append(". ");
                    break;
                }
            }
        }

        if (triggered) {
            return RiskIndicator.builder()
                    .ruleId(RULE_ID)
                    .description("URL matches known malicious domain patterns, phishing redirect chains, or confirmed threat indicators. " + evidence.toString().trim())
                    .points(POINTS)
                    .severity(SEVERITY)
                    .build();
        }

        return null;
    }

    private String extractDomain(String url) {
        try {
            java.net.URI uri = new java.net.URI(url.startsWith("http") ? url : "http://" + url);
            return uri.getHost() != null ? uri.getHost() : url;
        } catch (Exception e) {
            return url;
        }
    }
}
