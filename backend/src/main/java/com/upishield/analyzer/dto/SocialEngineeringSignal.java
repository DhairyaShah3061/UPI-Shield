package com.upishield.analyzer.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SocialEngineeringSignal {

    private String signalType;
    private String description;
    private String matchedText;
    private String severity; // LOW, MODERATE, STRONG
}
