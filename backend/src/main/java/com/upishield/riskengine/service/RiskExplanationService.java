package com.upishield.riskengine.service;

import com.upishield.riskengine.dto.RiskIndicator;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RiskExplanationService {

    public static final String DISCLAIMER = "This score is a risk index, not a calibrated probability of fraud.";

    public String generateRecommendation(String riskTier, List<RiskIndicator> indicators) {
        StringBuilder sb = new StringBuilder();

        switch (riskTier) {
            case "SAFE" -> {
                sb.append("Transaction appears safe. Always verify the recipient banking name before entering your UPI PIN.");
            }
            case "SUSPICIOUS" -> {
                sb.append("Elevated risk detected. Verify the requester independently through official channels before proceeding. Do not enter your PIN or share OTPs on an unverified request.");
            }
            case "HIGH_RISK" -> {
                sb.append("Stop immediately. Do not enter your UPI PIN, approve payment, or install any requested apps. This transaction exhibits strong characteristics of a known UPI fraud pattern.");
            }
            default -> {
                sb.append("Exercise caution and verify all recipient and transaction details independently.");
            }
        }

        return sb.toString();
    }

    public String getDisclaimer() {
        return DISCLAIMER;
    }
}
