package com.upishield.riskengine.rules;

import com.upishield.intelligence.dto.ThreatIndicatorDto;
import com.upishield.intelligence.service.ReputationService;
import com.upishield.riskengine.dto.RiskIndicator;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class VerifiedIndicatorRule implements RiskRule {

    public static final String RULE_ID = "RULE_VERIFIED_INDICATOR";
    private static final int POINTS = 50;
    private static final String SEVERITY = "STRONG";

    private final ReputationService reputationService;

    public VerifiedIndicatorRule(ReputationService reputationService) {
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

        StringBuilder evidence = new StringBuilder();

        // 1. Check Payee VPA from QR scan
        if (context.qrAnalysis() != null && context.qrAnalysis().getPaymentDetails() != null) {
            String vpa = context.qrAnalysis().getPaymentDetails().getPayeeVpa();
            if (vpa != null && !vpa.isBlank()) {
                Optional<ThreatIndicatorDto> threat = reputationService.lookupVpa(vpa);
                if (threat.isPresent() && threat.get().isVerified()) {
                    evidence.append("Payee VPA (").append(vpa).append(") matches a confirmed fraud indicator in shared threat intelligence. ");
                    return buildIndicator(evidence.toString().trim());
                }
            }
        }

        // 2. Check extracted VPAs from message analysis
        if (context.messageAnalysis() != null && context.messageAnalysis().getExtractedVpas() != null) {
            for (String vpa : context.messageAnalysis().getExtractedVpas()) {
                Optional<ThreatIndicatorDto> threat = reputationService.lookupVpa(vpa);
                if (threat.isPresent() && threat.get().isVerified()) {
                    evidence.append("Extracted VPA (").append(vpa).append(") is a verified malicious indicator. ");
                    return buildIndicator(evidence.toString().trim());
                }
            }
        }

        // 3. Check extracted phone numbers from message analysis
        if (context.messageAnalysis() != null && context.messageAnalysis().getExtractedPhones() != null) {
            for (String phone : context.messageAnalysis().getExtractedPhones()) {
                Optional<ThreatIndicatorDto> threat = reputationService.lookupPhone(phone);
                if (threat.isPresent() && threat.get().isVerified()) {
                    evidence.append("Associated phone number (").append(phone).append(") is a verified scam indicator. ");
                    return buildIndicator(evidence.toString().trim());
                }
            }
        }

        // 4. Check QR payload hash if available
        if (context.qrAnalysis() != null && context.qrAnalysis().getPayloadHash() != null) {
            String hash = context.qrAnalysis().getPayloadHash();
            Optional<ThreatIndicatorDto> threat = reputationService.lookupVpa(hash);
            if (threat.isPresent() && threat.get().isVerified()) {
                evidence.append("QR payload hash matches a verified malicious indicator. ");
                return buildIndicator(evidence.toString().trim());
            }
        }

        return null;
    }

    private RiskIndicator buildIndicator(String details) {
        return RiskIndicator.builder()
                .ruleId(RULE_ID)
                .description("VPA, phone number, or QR hash matches a verified threat indicator in the threat database. " + details)
                .points(POINTS)
                .severity(SEVERITY)
                .build();
    }
}
