package com.upishield.incident.controller;

import com.upishield.incident.dto.DisputeRequest;
import com.upishield.incident.dto.IncidentReportRequest;
import com.upishield.incident.dto.IncidentReportResponse;
import com.upishield.incident.dto.ModerationActionRequest;
import com.upishield.incident.service.IncidentService;
import com.upishield.incident.service.ModerationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class IncidentController {

    private final IncidentService incidentService;
    private final ModerationService moderationService;

    @PostMapping("/incidents")
    public ResponseEntity<IncidentReportResponse> submitReport(
            @Valid @RequestBody IncidentReportRequest request,
            Authentication authentication) {
        UUID userId = resolveUserId(authentication);
        IncidentReportResponse response = incidentService.submitReport(userId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/incidents/mine")
    public ResponseEntity<List<IncidentReportResponse>> getMyReports(Authentication authentication) {
        UUID userId = resolveUserId(authentication);
        List<IncidentReportResponse> reports = incidentService.getUserReports(userId);
        return ResponseEntity.ok(reports);
    }

    @PostMapping("/incidents/{id}/dispute")
    public ResponseEntity<IncidentReportResponse> disputeReport(
            @PathVariable("id") UUID id,
            @Valid @RequestBody DisputeRequest request,
            Authentication authentication) {
        UUID userId = resolveUserId(authentication);
        IncidentReportResponse response = incidentService.disputeReport(id, userId, request);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/admin/incidents/{id}")
    @PreAuthorize("hasAnyRole('MODERATOR_ADMIN', 'ADMIN')")
    public ResponseEntity<IncidentReportResponse> moderateReport(
            @PathVariable("id") UUID id,
            @Valid @RequestBody ModerationActionRequest request,
            Authentication authentication) {
        verifyAdminRole(authentication);
        UUID moderatorId = resolveUserId(authentication);
        IncidentReportResponse response = moderationService.moderateReport(id, moderatorId, request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/admin/incidents/pending")
    @PreAuthorize("hasAnyRole('MODERATOR_ADMIN', 'ADMIN')")
    public ResponseEntity<List<IncidentReportResponse>> getPendingReports(Authentication authentication) {
        verifyAdminRole(authentication);
        List<IncidentReportResponse> pendingReports = moderationService.getPendingReports();
        return ResponseEntity.ok(pendingReports);
    }

    private UUID resolveUserId(Authentication authentication) {
        if (authentication == null) {
            authentication = SecurityContextHolder.getContext().getAuthentication();
        }

        if (authentication == null || authentication.getName() == null) {
            throw new AccessDeniedException("User is not authenticated");
        }

        String principalName = authentication.getName();
        try {
            return UUID.fromString(principalName);
        } catch (IllegalArgumentException e) {
            // For standard username/email principals, generate a deterministic UUID
            return UUID.nameUUIDFromBytes(principalName.getBytes(StandardCharsets.UTF_8));
        }
    }

    private void verifyAdminRole(Authentication authentication) {
        if (authentication == null) {
            authentication = SecurityContextHolder.getContext().getAuthentication();
        }
        if (authentication == null) {
            throw new AccessDeniedException("Authentication required");
        }

        boolean isAdmin = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(auth -> "ROLE_ADMIN".equalsIgnoreCase(auth)
                        || "ROLE_MODERATOR_ADMIN".equalsIgnoreCase(auth)
                        || "ADMIN".equalsIgnoreCase(auth)
                        || "MODERATOR_ADMIN".equalsIgnoreCase(auth));

        if (!isAdmin) {
            throw new AccessDeniedException("Access denied: ADMIN role required");
        }
    }
}
