package com.upishield.riskengine.service;

import com.upishield.riskengine.dto.RiskIndicator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RiskScoreCalculator {

    @Value("${app.risk.safe-max:29}")
    private int safeMax = 29;

    @Value("${app.risk.suspicious-max:64}")
    private int suspiciousMax = 64;

    @Value("${app.risk.score-cap:100}")
    private int scoreCap = 100;

    public void setSafeMax(int safeMax) {
        this.safeMax = safeMax;
    }

    public void setSuspiciousMax(int suspiciousMax) {
        this.suspiciousMax = suspiciousMax;
    }

    public void setScoreCap(int scoreCap) {
        this.scoreCap = scoreCap;
    }

    public int calculateScore(List<RiskIndicator> indicators) {
        if (indicators == null || indicators.isEmpty()) {
            return 0;
        }

        int totalPoints = indicators.stream()
                .mapToInt(RiskIndicator::getPoints)
                .sum();

        return Math.min(Math.max(totalPoints, 0), scoreCap);
    }

    public int calculateScoreWithMultiplier(List<RiskIndicator> indicators, double multiplier) {
        if (indicators == null || indicators.isEmpty()) {
            return 0;
        }

        int totalPoints = indicators.stream()
                .mapToInt(RiskIndicator::getPoints)
                .sum();

        int multiplied = (int) Math.round(totalPoints * multiplier);
        return Math.min(Math.max(multiplied, 0), scoreCap);
    }

    public String determineRiskTier(int riskScore) {
        if (riskScore <= safeMax) {
            return "SAFE";
        } else if (riskScore <= suspiciousMax) {
            return "SUSPICIOUS";
        } else {
            return "HIGH_RISK";
        }
    }

    public int getSafeMax() {
        return safeMax;
    }

    public int getSuspiciousMax() {
        return suspiciousMax;
    }

    public int getScoreCap() {
        return scoreCap;
    }
}
