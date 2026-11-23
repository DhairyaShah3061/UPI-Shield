package com.upishield.incident.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.upishield.incident.dto.IncidentReportResponse;
import com.upishield.incident.dto.ModerationActionRequest;
import com.upishield.incident.entity.AuditLog;
import com.upishield.incident.entity.IncidentReport;
import com.upishield.incident.entity.IncidentStatus;
import com.upishield.incident.repository.AuditLogRepository;
import com.upishield.incident.repository.IncidentReportRepository;
import com.upishield.intelligence.entity.IndicatorStatus;
import com.upishield.intelligence.entity.ThreatIndicator;
import com.upishield.intelligence.repository.ThreatIndicatorRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class ModerationService {

    private final IncidentReportRepository incidentReportRepository;
    private final ThreatIndicatorRepository threatIndicatorRepository;
    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper;

    /**
     * Retrieve all reports currently pending moderation review.
     *
     * @return List of IncidentReportResponse DTOs
     */
    @Transactional(readOnly = true)
    public List<IncidentReportResponse> getPendingReports() {
        return incidentReportRepository.findByStatus(IncidentStatus.PENDING)
                .stream()
                .map(this::mapToResponse)
                .toList();
    }

    /**
     * Apply a moderation decision to an incident report.
     * Updates the incident report status, updates indicator confidence score and status,
     * and logs the administrative action in the immutable audit_logs table.
     *
     * @param reportId the incident report ID
     * @param moderatorId the UUID of the admin / moderator
     * @param request the moderation action details (VERIFY, DISMISS, REVIEW)
     * @return updated IncidentReportResponse
     */
    @Transactional
    public IncidentReportResponse moderateReport(UUID reportId, UUID moderatorId, ModerationActionRequest request) {
        IncidentReport report = incidentReportRepository.findById(reportId)
                .orElseThrow(() -> new IllegalArgumentException("Incident report not found with id: " + reportId));

        String actionUpper = request.getAction().trim().toUpperCase(Locale.ROOT);
        IncidentStatus oldStatus = report.getStatus();
        IncidentStatus newStatus;
        IndicatorStatus newIndicatorStatus;
        double confidenceDelta;

        switch (actionUpper) {
            case "VERIFY", "VERIFIED" -> {
                newStatus = IncidentStatus.VERIFIED;
                newIndicatorStatus = IndicatorStatus.VERIFIED;
                confidenceDelta = 50.0;
            }
            case "DISMISS", "DISMISSED" -> {
                newStatus = IncidentStatus.DISMISSED;
                newIndicatorStatus = IndicatorStatus.DISMISSED;
                confidenceDelta = -30.0;
            }
            case "REVIEW", "UNDER_REVIEW" -> {
                newStatus = IncidentStatus.UNDER_REVIEW;
                newIndicatorStatus = IndicatorStatus.UNDER_REVIEW;
                confidenceDelta = 0.0;
            }
            default -> throw new IllegalArgumentException("Invalid moderation action: " + request.getAction() 
                    + ". Expected VERIFY, DISMISS, or REVIEW.");
        }

        report.setStatus(newStatus);
        report.setModeratorId(moderatorId);
        report.setUpdatedAt(Instant.now());
        IncidentReport updatedReport = incidentReportRepository.save(report);

        ThreatIndicator updatedIndicator = null;
        if (report.getIndicatorId() != null) {
            Optional<ThreatIndicator> indicatorOpt = threatIndicatorRepository.findById(report.getIndicatorId());
            if (indicatorOpt.isPresent()) {
                ThreatIndicator indicator = indicatorOpt.get();
                indicator.setStatus(newIndicatorStatus);
                double newConfidence = Math.max(0.0, Math.min(100.0, indicator.getConfidenceScore() + confidenceDelta));
                if ("VERIFY".equals(actionUpper) || "VERIFIED".equals(actionUpper)) {
                    newConfidence = Math.max(newConfidence, 85.0);
                }
                indicator.setConfidenceScore(newConfidence);
                indicator.setLastSeen(Instant.now());
                updatedIndicator = threatIndicatorRepository.save(indicator);
            }
        }

        // Record immutable audit log entry
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("reportId", reportId.toString());
        metadata.put("moderatorId", moderatorId != null ? moderatorId.toString() : null);
        metadata.put("action", actionUpper);
        metadata.put("previousStatus", oldStatus != null ? oldStatus.name() : null);
        metadata.put("newStatus", newStatus.name());
        metadata.put("notes", request.getNotes());
        if (report.getIndicatorId() != null) {
            metadata.put("indicatorId", report.getIndicatorId().toString());
            if (updatedIndicator != null) {
                metadata.put("indicatorStatus", updatedIndicator.getStatus().name());
                metadata.put("indicatorConfidence", updatedIndicator.getConfidenceScore());
            }
        }

        String metadataJson;
        try {
            metadataJson = objectMapper.writeValueAsString(metadata);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize audit log metadata", e);
            metadataJson = "{}";
        }

        AuditLog auditLog = AuditLog.builder()
                .actorId(moderatorId)
                .actionType("MODERATE_REPORT_" + actionUpper)
                .targetEntity("INCIDENT_REPORT:" + reportId)
                .metadataJson(metadataJson)
                .createdAt(Instant.now())
                .build();
        auditLogRepository.save(auditLog);

        return mapToResponse(updatedReport);
    }

    private IncidentReportResponse mapToResponse(IncidentReport report) {
        String indicatorType = null;
        String displayMasked = null;

        if (report.getIndicatorId() != null) {
            ThreatIndicator indicator = threatIndicatorRepository.findById(report.getIndicatorId()).orElse(null);
            if (indicator != null) {
                indicatorType = indicator.getIndicatorType();
                displayMasked = indicator.getDisplayMasked();
            }
        }

        return IncidentReportResponse.builder()
                .id(report.getId())
                .indicatorType(indicatorType)
                .displayMasked(displayMasked)
                .status(report.getStatus().name())
                .scamCategory(report.getScamCategory())
                .createdAt(report.getCreatedAt())
                .build();
    }
}
