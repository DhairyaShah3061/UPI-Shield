package com.upishield.riskengine.controller;

import com.upishield.common.dto.ApiResponse;
import com.upishield.common.util.CredentialSanitizer;
import com.upishield.riskengine.dto.RiskAssessmentRequest;
import com.upishield.riskengine.dto.RiskAssessmentResponse;
import com.upishield.riskengine.entity.ScanHistory;
import com.upishield.riskengine.repository.ScanHistoryRepository;
import com.upishield.riskengine.service.RiskAssessmentEngine;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/risk")
public class RiskController {

    private final RiskAssessmentEngine riskAssessmentEngine;
    private final ScanHistoryRepository scanHistoryRepository;

    public RiskController(
            RiskAssessmentEngine riskAssessmentEngine,
            ScanHistoryRepository scanHistoryRepository) {
        this.riskAssessmentEngine = riskAssessmentEngine;
        this.scanHistoryRepository = scanHistoryRepository;
    }

    @PostMapping("/assess")
    public ResponseEntity<ApiResponse<RiskAssessmentResponse>> assessRisk(
            @Valid @RequestBody RiskAssessmentRequest request) {
        CredentialSanitizer.validateNoCredentials(request.getMessageContent());
        CredentialSanitizer.validateNoCredentials(request.getQrPayload());
        CredentialSanitizer.validateNoCredentials(request.getUrl());
        CredentialSanitizer.validateNoCredentials(request.getPayeeVpa());
        log.info("Received risk assessment request for input types: qr={}, msg={}, url={}",
                request.getQrPayload() != null,
                request.getMessageContent() != null,
                request.getUrl() != null);

        RiskAssessmentResponse response = riskAssessmentEngine.assessRisk(request);
        return ResponseEntity.ok(ApiResponse.success("Risk assessment completed successfully", response));
    }

    @GetMapping("/history")
    public ResponseEntity<ApiResponse<Page<ScanHistory>>> getHistory(
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        UUID userId = resolveCurrentUserId();
        log.info("Fetching paginated scan history for user: {}", userId);

        Page<ScanHistory> history = scanHistoryRepository.findByUserIdOrderByCreatedAtDesc(userId, pageable);
        return ResponseEntity.ok(ApiResponse.success("Scan history retrieved successfully", history));
    }

    private UUID resolveCurrentUserId() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
                String name = auth.getName();
                try {
                    return UUID.fromString(name);
                } catch (IllegalArgumentException e) {
                    return UUID.nameUUIDFromBytes(name.getBytes(StandardCharsets.UTF_8));
                }
            }
        } catch (Exception e) {
            log.debug("No authenticated user found in SecurityContext");
        }
        return UUID.fromString("00000000-0000-0000-0000-000000000000");
    }
}
