package com.upishield.riskengine.rules;

import com.upishield.riskengine.dto.RiskIndicator;
import org.springframework.stereotype.Component;

@Component
public class RemoteAppRule implements RiskRule {

    public static final String RULE_ID = "RULE_REMOTE_APP";
    private static final int POINTS = 30;
    private static final String SEVERITY = "STRONG";

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
            if (context.messageAnalysis().isRemoteAppDetected()) {
                triggered = true;
                evidence.append("Message analysis detected request to install remote access or screen sharing app. ");
            } else if (context.messageAnalysis().getSignals() != null) {
                boolean hasSignal = context.messageAnalysis().getSignals().stream()
                        .anyMatch(s -> "REMOTE_ACCESS_APP".equalsIgnoreCase(s.getSignalType()) || "REMOTE_APP".equalsIgnoreCase(s.getSignalType()));
                if (hasSignal) {
                    triggered = true;
                    evidence.append("Signal detected indicating remote desktop or APK installation. ");
                }
            }

            // Keyword check in original message
            if (!triggered && context.messageAnalysis().getOriginalContent() != null) {
                String lower = context.messageAnalysis().getOriginalContent().toLowerCase();
                if (lower.contains("anydesk") || lower.contains("teamviewer") || lower.contains("quicksupport") 
                        || lower.contains("rustdesk") || lower.contains("screen share") || lower.contains("install apk")) {
                    triggered = true;
                    evidence.append("Message mentions known remote access tool or APK. ");
                }
            }
        }

        // 2. Check context Q&A answers
        if (!triggered && (context.isAnswerTrue("remote_app") || context.isAnswerTrue("remote_access") || context.isAnswerTrue("screen_sharing"))) {
            triggered = true;
            evidence.append("User confirmed requester asked them to install a screen-sharing or remote desktop application. ");
        }

        if (triggered) {
            return RiskIndicator.builder()
                    .ruleId(RULE_ID)
                    .description("Remote access app installation detected. Scammers use screen-sharing apps (such as AnyDesk, TeamViewer, QuickSupport) to view OTPs and take control of your device. " + evidence.toString().trim())
                    .points(POINTS)
                    .severity(SEVERITY)
                    .build();
        }

        return null;
    }
}
