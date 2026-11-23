package com.upishield.intelligence.dto;

import com.upishield.intelligence.entity.ThreatIndicator;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ThreatIndicatorDto implements Serializable {

    private static final long serialVersionUID = 1L;

    private UUID id;
    private String indicatorType;
    private String indicatorHash;
    private String displayMasked;
    private String status;
    private double confidenceScore;
    private int reportCount;
    private Instant firstSeen;
    private Instant lastSeen;

    public boolean isVerified() {
        return "VERIFIED".equalsIgnoreCase(status);
    }

    public static ThreatIndicatorDto fromEntity(ThreatIndicator entity) {
        if (entity == null) {
            return null;
        }
        return ThreatIndicatorDto.builder()
                .id(entity.getId())
                .indicatorType(entity.getIndicatorType())
                .indicatorHash(entity.getIndicatorHash())
                .displayMasked(entity.getDisplayMasked())
                .status(entity.getStatus() != null ? entity.getStatus().name() : null)
                .confidenceScore(entity.getConfidenceScore())
                .reportCount(entity.getReportCount())
                .firstSeen(entity.getFirstSeen())
                .lastSeen(entity.getLastSeen())
                .build();
    }
}
