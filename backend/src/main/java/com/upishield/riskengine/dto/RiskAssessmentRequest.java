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
public class RiskAssessmentRequest {

    private String messageContent;
    private String qrPayload;
    private String url;
    private String payeeVpa;
    private String paymentAmount;
    private String paymentPurpose;
    private boolean isNewBeneficiary;
    private List<ContextAnswer> contextAnswers;
}
