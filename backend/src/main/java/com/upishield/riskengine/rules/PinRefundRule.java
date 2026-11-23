package com.upishield.riskengine.rules;

import com.upishield.riskengine.dto.RiskIndicator;
import org.springframework.stereotype.Component;

@Component
public class PinRefundRule implements RiskRule {

    public static final String RULE_ID = "RULE_PIN_REFUND";
    private static final int POINTS = 45;
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
            if (context.messageAnalysis().isPinRequestDetected()) {
                triggered = true;
                evidence.append("Message instructs entering UPI PIN to receive money or refund. ");
            } else if (context.messageAnalysis().getSignals() != null) {
                boolean hasSignal = context.messageAnalysis().getSignals().stream()
                        .anyMatch(s -> "PIN_TO_RECEIVE".equalsIgnoreCase(s.getSignalType())
                                || "PIN_FOR_RECEIVE".equalsIgnoreCase(s.getSignalType())
                                || "PIN_CLAIM".equalsIgnoreCase(s.getSignalType())
                                || "REFUND".equalsIgnoreCase(s.getSignalType()));
                if (hasSignal) {
                    triggered = true;
                    evidence.append("Signal detected indicating PIN required to receive money. ");
                }
            }
        }

        // 2. Check QR analysis
        if (!triggered && context.qrAnalysis() != null) {
            if (context.qrAnalysis().isClaimsPinToReceive()) {
                triggered = true;
                evidence.append("QR payload context claims UPI PIN is needed to receive payment. ");
            } else if (context.qrAnalysis().getPaymentDetails() != null) {
                String note = context.qrAnalysis().getPaymentDetails().getTransactionNote();
                if (note != null) {
                    String lowerNote = note.toLowerCase();
                    if (lowerNote.contains("pin") && (lowerNote.contains("refund") || lowerNote.contains("receive") || lowerNote.contains("cashback"))) {
                        triggered = true;
                        evidence.append("QR transaction note implies PIN entry for refund: ").append(note).append(". ");
                    }
                }
            }
        }

        // 3. Check payment purpose
        if (!triggered && context.paymentPurpose() != null) {
            String lowerPurpose = context.paymentPurpose().toLowerCase();
            if (lowerPurpose.contains("refund") || lowerPurpose.contains("claim cashback") || lowerPurpose.contains("receive money")) {
                // If context is debit/pay with a claim to receive/refund
                triggered = true;
                evidence.append("Payment purpose indicates refund/credit claim: ").append(context.paymentPurpose()).append(". ");
            }
        }

        // 4. Check user context answers
        if (!triggered && (context.isAnswerTrue("pin_to_receive") || context.isAnswerTrue("pin_refund"))) {
            triggered = true;
            evidence.append("User confirmed being instructed to enter UPI PIN to receive funds or a refund. ");
        }

        if (triggered) {
            return RiskIndicator.builder()
                    .ruleId(RULE_ID)
                    .description("Request claims UPI PIN is required to receive money or a refund. In UPI, PIN is strictly used to AUTHORIZE PAYMENTS out of your account, never to receive funds. " + evidence.toString().trim())
                    .points(POINTS)
                    .severity(SEVERITY)
                    .build();
        }

        return null;
    }
}
