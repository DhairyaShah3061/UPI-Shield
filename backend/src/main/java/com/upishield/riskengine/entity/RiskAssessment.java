package com.upishield.riskengine.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "risk_assessments")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RiskAssessment {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(name = "scan_id", nullable = false)
    private UUID scanId;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Column(name = "risk_tier", nullable = false, length = 20)
    private String riskTier;

    @Column(name = "indicators_json", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private String indicatorsJson;

    @Column(name = "context_answers_json", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private String contextAnswersJson;

    @Column(name = "recommendation", columnDefinition = "text")
    private String recommendation;

    @Column(name = "latency_ms")
    private Integer latencyMs;

    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();
}
