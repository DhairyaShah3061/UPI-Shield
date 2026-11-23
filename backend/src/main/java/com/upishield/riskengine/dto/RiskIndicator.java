package com.upishield.riskengine.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RiskIndicator {

    private String ruleId;
    private String description;
    private int points;
    private String severity;
}
