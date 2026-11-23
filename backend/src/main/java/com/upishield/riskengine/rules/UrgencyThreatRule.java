package com.upishield.riskengine.rules;

import com.upishield.riskengine.dto.RiskIndicator;
import org.springframework.stereotype.Component;

@Component
public class UrgencyThreatRule implements RiskRule {

    public static final String RULE_ID = "RULE_URGENCY_THREAT";
    private static final int POINTS = 15;
    private static final String SEVERITY = "MODERATE";

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

        // 1. Check message analysis
        if (context.messageAnalysis() != null) {
            if (context.messageAnalysis().isUrgencyDetected() || context.messageAnalysis().isThreatDetected()) {
                triggered = true;
                evidence.append("Message analysis detected coercive urgency or threat cues. ");
            } else if (context.messageAnalysis().getSignals() != null) {
                boolean hasSignal = context.messageAnalysis().getSignals().stream()
                        .anyMatch(s -> "ARTIFICIAL_URGENCY".equalsIgnoreCase(s.getSignalType())
                                || "URGENCY".equalsIgnoreCase(s.getSignalType())
                                || "URGENCY_THREAT".equalsIgnoreCase(s.getSignalType())
                                || "INTIMIDATION".equalsIgnoreCase(s.getSignalType())
                                || "THREAT".equalsIgnoreCase(s.getSignalType()));
                if (hasSignal) {
                    triggered = true;
                    evidence.append("Artificial urgency or intimidation signal detected. ");
                }
            }

            // Keyword check
            if (!triggered && context.messageAnalysis().getOriginalContent() != null) {
                String lower = context.messageAnalysis().getOriginalContent().toLowerCase();
                if (lower.contains("disconnection tonight") || lower.contains("electricity will be disconnected") 
                        || lower.contains("account blocked") || lower.contains("immediate action") 
                        || lower.contains("within 2 hours") || lower.contains("police complaint") 
                        || lower.contains("court notice") || lower.contains("sim blocked")) {
                    triggered = true;
                    evidence.append("Message contains coercive threat or artificial deadline keywords. ");
                }
            }
        }

        // 2. Check context Q&A answers
        if (!triggered && (context.isAnswerTrue("urgency_threat") || context.isAnswerTrue("live_call") || context.isAnswerTrue("urgency"))) {
            triggered = true;
            evidence.append("User confirmed being subjected to urgency, intimidation, or a continuous live phone call. ");
        }

        if (triggered) {
            return RiskIndicator.builder()
                    .ruleId(RULE_ID)
                    .description("Artificial urgency or intimidation detected. Fraudsters induce panic (e.g. utility disconnection, account freeze) to rush victims into making hasty payments. " + evidence.toString().trim())
                    .points(POINTS)
                    .severity(SEVERITY)
                    .build();
        }

        return null;
    }
}
