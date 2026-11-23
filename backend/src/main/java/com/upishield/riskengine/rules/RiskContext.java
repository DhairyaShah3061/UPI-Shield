package com.upishield.riskengine.rules;

import com.upishield.analyzer.dto.MessageAnalysisResponse;
import com.upishield.analyzer.dto.UrlAnalysisResponse;
import com.upishield.riskengine.dto.ContextAnswer;
import com.upishield.scanner.dto.QRScanResponse;

import java.util.List;

public record RiskContext(
        MessageAnalysisResponse messageAnalysis,
        QRScanResponse qrAnalysis,
        UrlAnalysisResponse urlAnalysis,
        List<ContextAnswer> contextAnswers,
        boolean isNewBeneficiary,
        String paymentAmount,
        String paymentPurpose
) {

    public boolean hasContextAnswer(String questionId) {
        if (contextAnswers == null || questionId == null) {
            return false;
        }
        return contextAnswers.stream()
                .anyMatch(a -> questionId.equalsIgnoreCase(a.getQuestionId()));
    }

    public Boolean getContextAnswerValue(String questionId) {
        if (contextAnswers == null || questionId == null) {
            return null;
        }
        return contextAnswers.stream()
                .filter(a -> questionId.equalsIgnoreCase(a.getQuestionId()))
                .map(ContextAnswer::isAnswer)
                .findFirst()
                .orElse(null);
    }

    public boolean isAnswerTrue(String questionId) {
        Boolean val = getContextAnswerValue(questionId);
        return Boolean.TRUE.equals(val);
    }
}
