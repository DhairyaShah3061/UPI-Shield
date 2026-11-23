package com.upishield.incident.service;

import com.upishield.incident.dto.DisputeRequest;
import com.upishield.incident.dto.IncidentReportRequest;
import com.upishield.incident.dto.IncidentReportResponse;
import com.upishield.incident.entity.IncidentReport;
import com.upishield.incident.entity.IncidentStatus;
import com.upishield.incident.repository.IncidentReportRepository;
import com.upishield.intelligence.entity.IndicatorStatus;
import com.upishield.intelligence.entity.ThreatIndicator;
import com.upishield.intelligence.repository.ThreatIndicatorRepository;
import com.upishield.intelligence.service.HashingService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class IncidentService {

    private final IncidentReportRepository incidentReportRepository;
    private final ThreatIndicatorRepository threatIndicatorRepository;
    private final HashingService hashingService;

    /**
     * Submit a new consent-based incident report.
     * Validates consent, normalizes and hashes the indicator value, creates or updates
     * a ThreatIndicator entity (status UNVERIFIED), and persists the IncidentReport (status PENDING).
     *
     * @param userId the ID of the reporting user
     * @param request the incident report payload
     * @return IncidentReportResponse
     */
    @Transactional
    public IncidentReportResponse submitReport(UUID userId, IncidentReportRequest request) {
        if (!request.isConsentGiven()) {
            throw new IllegalArgumentException("User consent must be explicitly given to submit an incident report.");
        }

        String normalizedType = request.getIndicatorType() != null 
                ? request.getIndicatorType().trim().toUpperCase(Locale.ROOT) 
                : "UNKNOWN";
        String indicatorHash = hashingService.normalizeAndHash(request.getIndicatorValue());
        String displayMasked = hashingService.maskForDisplay(request.getIndicatorValue(), normalizedType);

        ThreatIndicator indicator = threatIndicatorRepository.findByIndicatorHash(indicatorHash)
                .map(existing -> {
                    existing.setReportCount(existing.getReportCount() + 1);
                    existing.setLastSeen(Instant.now());
                    if (existing.getDisplayMasked() == null || existing.getDisplayMasked().isBlank()) {
                        existing.setDisplayMasked(displayMasked);
                    }
                    return threatIndicatorRepository.save(existing);
                })
                .orElseGet(() -> {
                    ThreatIndicator newIndicator = ThreatIndicator.builder()
                            .indicatorType(normalizedType)
                            .indicatorHash(indicatorHash)
                            .displayMasked(displayMasked)
                            .status(IndicatorStatus.UNVERIFIED)
                            .confidenceScore(10.0)
                            .reportCount(1)
                            .firstSeen(Instant.now())
                            .lastSeen(Instant.now())
                            .build();
                    return threatIndicatorRepository.save(newIndicator);
                });

        Instant now = Instant.now();
        IncidentReport report = IncidentReport.builder()
                .reporterId(userId)
                .indicatorId(indicator.getId())
                .scamCategory(request.getScamCategory())
                .redactedSummary(request.getRedactedSummary())
                .status(IncidentStatus.PENDING)
                .createdAt(now)
                .updatedAt(now)
                .build();

        IncidentReport saved = incidentReportRepository.save(report);

        return IncidentReportResponse.builder()
                .id(saved.getId())
                .indicatorType(indicator.getIndicatorType())
                .displayMasked(indicator.getDisplayMasked())
                .status(saved.getStatus().name())
                .scamCategory(saved.getScamCategory())
                .createdAt(saved.getCreatedAt())
                .build();
    }

    /**
     * Retrieve all incident reports submitted by a specific user.
     *
     * @param userId reporter UUID
     * @return List of IncidentReportResponse DTOs
     */
    @Transactional(readOnly = true)
    public List<IncidentReportResponse> getUserReports(UUID userId) {
        List<IncidentReport> reports = incidentReportRepository.findByReporterId(userId);
        return reports.stream().map(this::mapToResponse).toList();
    }

    /**
     * File a formal dispute against an incident report.
     * Sets the status of the report (and its linked indicator) to DISPUTED.
     *
     * @param reportId report UUID
     * @param userId user UUID initiating dispute
     * @param request dispute payload with reason
     * @return updated IncidentReportResponse
     */
    @Transactional
    public IncidentReportResponse disputeReport(UUID reportId, UUID userId, DisputeRequest request) {
        IncidentReport report = incidentReportRepository.findById(reportId)
                .orElseThrow(() -> new IllegalArgumentException("Incident report not found with id: " + reportId));

        report.setStatus(IncidentStatus.DISPUTED);
        report.setDisputeReason(request.getReason());
        report.setUpdatedAt(Instant.now());
        IncidentReport saved = incidentReportRepository.save(report);

        if (report.getIndicatorId() != null) {
            threatIndicatorRepository.findById(report.getIndicatorId()).ifPresent(indicator -> {
                indicator.setStatus(IndicatorStatus.DISPUTED);
                indicator.setLastSeen(Instant.now());
                threatIndicatorRepository.save(indicator);
            });
        }

        return mapToResponse(saved);
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
