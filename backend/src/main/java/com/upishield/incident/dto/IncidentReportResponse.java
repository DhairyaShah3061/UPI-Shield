package com.upishield.incident.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IncidentReportResponse {

    private UUID id;
    private String indicatorType;
    private String displayMasked;
    private String status;
    private String scamCategory;
    private Instant createdAt;
}
