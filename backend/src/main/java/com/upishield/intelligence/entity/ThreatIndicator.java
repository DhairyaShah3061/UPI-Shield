package com.upishield.intelligence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "threat_indicators")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ThreatIndicator {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "indicator_type", nullable = false, length = 20)
    private String indicatorType;

    @Column(name = "indicator_hash", nullable = false, unique = true, length = 64)
    private String indicatorHash;

    @Column(name = "display_masked", length = 255)
    private String displayMasked;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    @Builder.Default
    private IndicatorStatus status = IndicatorStatus.UNVERIFIED;

    @Column(name = "confidence_score", nullable = false)
    @Builder.Default
    private double confidenceScore = 0.0;

    @Column(name = "report_count", nullable = false)
    @Builder.Default
    private int reportCount = 0;

    @Column(name = "first_seen", nullable = false)
    private Instant firstSeen;

    @Column(name = "last_seen", nullable = false)
    private Instant lastSeen;

    @PrePersist
    protected void onCreate() {
        Instant now = Instant.now();
        if (firstSeen == null) {
            firstSeen = now;
        }
        if (lastSeen == null) {
            lastSeen = now;
        }
        if (status == null) {
            status = IndicatorStatus.UNVERIFIED;
        }
    }
}
