package com.upishield.riskengine.rules;

import com.upishield.riskengine.dto.RiskIndicator;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class NewBeneficiaryContextRule implements RiskRule {

    public static final String RULE_ID = "RULE_NEW_BEN_CONTEXT";
    private static final int POINTS = 10;
    private static final String SEVERITY = "MODERATE";

    private static final Set<String> UNUSUAL_KEYWORDS = Set.of(
            "prize", "reward", "lottery", "cashback", "refund", "kyc", 
            "verification", "bonus", "gift", "offer", "winner", "electricity bill"
    );

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public RiskIndicator evaluate(RiskContext context) {
        if (context == null) {
            return null;
        }

        // Guardrail per FR-15: Never trigger on new beneficiary alone
        if (!context.isNewBeneficiary()) {
            return null;
        }

        boolean hasUnusualContext = false;
        StringBuilder evidence = new StringBuilder();

        // 1. Check payment purpose
        if (context.paymentPurpose() != null && !context.paymentPurpose().isBlank()) {
            String lowerPurpose = context.paymentPurpose().toLowerCase();
            for (String keyword : UNUSUAL_KEYWORDS) {
                if (lowerPurpose.contains(keyword)) {
                    hasUnusualContext = true;
                    evidence.append("Payment purpose '").append(context.paymentPurpose())
                            .append("' matches high-risk pretext keyword '").append(keyword).append("'. ");
                    break;
                }
            }
        }

        // 2. Check message content/signals
        if (!hasUnusualContext && context.messageAnalysis() != null) {
            String content = context.messageAnalysis().getOriginalContent();
            if (content != null) {
                String lowerContent = content.toLowerCase();
                for (String keyword : UNUSUAL_KEYWORDS) {
                    if (lowerContent.contains(keyword)) {
                        hasUnusualContext = true;
                        evidence.append("Message context references unusual pretext: '").append(keyword).append("'. ");
                        break;
                    }
                }
            }
        }

        // 3. Check contextual answers (e.g. user answered prize/lottery/refund question)
        if (!hasUnusualContext && (context.isAnswerTrue("prize_claim") || context.isAnswerTrue("official_channel"))) {
            hasUnusualContext = true;
            evidence.append("User confirmed payment is linked to a prize claim or unverified communication channel. ");
        }

        // ONLY trigger when new beneficiary AND unusual context are BOTH present
        if (hasUnusualContext) {
            return RiskIndicator.builder()
                    .ruleId(RULE_ID)
                    .description("First-time payment to an unknown beneficiary combined with an unusual pretext (prize, refund, or KYC verification). " + evidence.toString().trim())
                    .points(POINTS)
                    .severity(SEVERITY)
                    .build();
        }

        return null;
    }
}
