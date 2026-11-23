package com.upishield.incident.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IncidentReportRequest {

    @NotBlank(message = "indicatorType is required")
    private String indicatorType;

    @NotBlank(message = "indicatorValue is required")
    private String indicatorValue;

    private String scamCategory;

    private String redactedSummary;

    @AssertTrue(message = "User consent must be explicitly given to submit an incident report")
    private boolean consentGiven;
}
