package com.upishield.riskengine.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RiskAssessmentResponse {

    private int riskScore;
    private String riskTier;
    private List<RiskIndicator> indicators;
    private String recommendation;
    private List<ContextQuestion> pendingQuestions;
    private String disclaimer;
}
