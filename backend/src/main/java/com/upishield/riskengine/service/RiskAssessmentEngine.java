package com.upishield.riskengine.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.upishield.analyzer.dto.MessageAnalysisResponse;
import com.upishield.analyzer.dto.UrlAnalysisResponse;
import com.upishield.analyzer.service.MessageAnalyzer;
import com.upishield.analyzer.service.URLAnalyzer;
import com.upishield.riskengine.dto.*;
import com.upishield.riskengine.entity.RiskAssessment;
import com.upishield.riskengine.entity.ScanHistory;
import com.upishield.riskengine.repository.RiskAssessmentRepository;
import com.upishield.riskengine.repository.ScanHistoryRepository;
import com.upishield.riskengine.rules.RiskContext;
import com.upishield.riskengine.rules.RiskRule;
import com.upishield.scanner.dto.QRScanResponse;
import com.upishield.scanner.service.QRDecoder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

@Slf4j
@Service
public class RiskAssessmentEngine {

    private final MessageAnalyzer messageAnalyzer;
    private final QRDecoder qrDecoder;
    private final URLAnalyzer urlAnalyzer;
    private final List<RiskRule> riskRules;
    private final RiskScoreCalculator scoreCalculator;
    private final RiskExplanationService explanationService;
    private final ScanHistoryRepository scanHistoryRepository;
    private final RiskAssessmentRepository riskAssessmentRepository;
    private final ObjectMapper objectMapper;

    public RiskAssessmentEngine(
            MessageAnalyzer messageAnalyzer,
            QRDecoder qrDecoder,
            URLAnalyzer urlAnalyzer,
            List<RiskRule> riskRules,
            RiskScoreCalculator scoreCalculator,
            RiskExplanationService explanationService,
            ScanHistoryRepository scanHistoryRepository,
            RiskAssessmentRepository riskAssessmentRepository,
            ObjectMapper objectMapper) {
        this.messageAnalyzer = messageAnalyzer;
        this.qrDecoder = qrDecoder;
        this.urlAnalyzer = urlAnalyzer;
        this.riskRules = riskRules;
        this.scoreCalculator = scoreCalculator;
        this.explanationService = explanationService;
        this.scanHistoryRepository = scanHistoryRepository;
        this.riskAssessmentRepository = riskAssessmentRepository;
        this.objectMapper = objectMapper;
    }

    public RiskAssessmentResponse assessRisk(RiskAssessmentRequest request) {
        long startTime = System.currentTimeMillis();

        // 1. Analyze inputs based on provided request parameters
        MessageAnalysisResponse messageAnalysis = null;
        if (request.getMessageContent() != null && !request.getMessageContent().isBlank()) {
            messageAnalysis = messageAnalyzer.analyze(request.getMessageContent());
        }

        QRScanResponse qrAnalysis = null;
        if (request.getQrPayload() != null && !request.getQrPayload().isBlank()) {
            qrAnalysis = qrDecoder.decode(request.getQrPayload());
        }

        UrlAnalysisResponse urlAnalysis = null;
        if (request.getUrl() != null && !request.getUrl().isBlank()) {
            urlAnalysis = urlAnalyzer.analyze(request.getUrl());
        }

        // 2. Build RiskContext from all extracted and input signals
        RiskContext context = new RiskContext(
                messageAnalysis,
                qrAnalysis,
                urlAnalysis,
                request.getContextAnswers(),
                request.isNewBeneficiary(),
                request.getPaymentAmount(),
                request.getPaymentPurpose()
        );

        // 3. Layer 1: Evaluate deterministic rules
        List<RiskIndicator> indicators = new ArrayList<>();
        Set<String> triggeredRuleIds = new HashSet<>();

        for (RiskRule rule : riskRules) {
            try {
                RiskIndicator indicator = rule.evaluate(context);
                if (indicator != null) {
                    indicators.add(indicator);
                    triggeredRuleIds.add(rule.getRuleId());
                }
            } catch (Exception e) {
                log.error("Error evaluating rule {}", rule.getRuleId(), e);
            }
        }

        // 4. Layer 2: Check compound patterns (e.g., new beneficiary + urgency + refund claim)
        boolean hasPinRefund = triggeredRuleIds.contains("RULE_PIN_REFUND");
        boolean hasUrgency = triggeredRuleIds.contains("RULE_URGENCY_THREAT");
        boolean hasNewBeneficiary = context.isNewBeneficiary();

        if (hasNewBeneficiary && hasUrgency && hasPinRefund) {
            indicators.add(RiskIndicator.builder()
                    .ruleId("RULE_COMPOUND_SOCIAL_ENGINEERING")
                    .description("High-risk compound manipulation pattern: First-time beneficiary combined with artificial urgency and refund/PIN claim multiplier.")
                    .points(20)
                    .severity("STRONG")
                    .build());
        } else if (hasNewBeneficiary && hasUrgency && triggeredRuleIds.contains("RULE_REMOTE_APP")) {
            indicators.add(RiskIndicator.builder()
                    .ruleId("RULE_COMPOUND_REMOTE_TAKEOVER")
                    .description("High-risk compound manipulation pattern: First-time beneficiary combined with urgent remote access application install.")
                    .points(25)
                    .severity("STRONG")
                    .build());
        }

        // 5. Calculate unified risk score
        int riskScore = scoreCalculator.calculateScore(indicators);
        String riskTier = scoreCalculator.determineRiskTier(riskScore);

        // 6. Generate explainable recommendations and disclaimer
        String recommendation = explanationService.generateRecommendation(riskTier, indicators);
        String disclaimer = explanationService.getDisclaimer();

        // 7. Check ambiguous range (30-64) for pending contextual questions
        List<ContextQuestion> pendingQuestions = null;
        boolean isAmbiguous = (riskScore >= scoreCalculator.getSafeMax() + 1 && riskScore <= scoreCalculator.getSuspiciousMax());
        boolean hasNoContextAnswers = (request.getContextAnswers() == null || request.getContextAnswers().isEmpty());

        if (isAmbiguous && hasNoContextAnswers) {
            pendingQuestions = generatePendingQuestions(context, triggeredRuleIds);
        }

        long latencyMs = System.currentTimeMillis() - startTime;

        // 8. Persist scan history and risk assessment records
        persistAssessment(request, riskScore, riskTier, indicators, request.getContextAnswers(), recommendation, (int) latencyMs);

        // 9. Build and return response
        return RiskAssessmentResponse.builder()
                .riskScore(riskScore)
                .riskTier(riskTier)
                .indicators(indicators)
                .recommendation(recommendation)
                .pendingQuestions(pendingQuestions)
                .disclaimer(disclaimer)
                .build();
    }

    private List<ContextQuestion> generatePendingQuestions(RiskContext context, Set<String> triggeredRules) {
        List<ContextQuestion> questions = new ArrayList<>();

        questions.add(ContextQuestion.builder()
                .questionId("pin_to_receive")
                .questionText("Were you told to enter your UPI PIN to receive money, cashback, or a refund?")
                .context("Entering your PIN authorizes money leaving your account, never receiving funds.")
                .build());

        questions.add(ContextQuestion.builder()
                .questionId("remote_access")
                .questionText("Did someone ask you to install an app like AnyDesk, TeamViewer, or QuickSupport?")
                .context("Scammers use remote access apps to view your screen and capture credentials.")
                .build());

        questions.add(ContextQuestion.builder()
                .questionId("live_call")
                .questionText("Are you currently on a phone call or being pressured by someone while making this payment?")
                .context("Scammers often keep victims on live calls to prevent independent verification.")
                .build());

        questions.add(ContextQuestion.builder()
                .questionId("official_channel")
                .questionText("Did this payment request come through an unverified SMS, WhatsApp, or phone number?")
                .context("Utility companies and banks do not disconnect services via personal phone numbers.")
                .build());

        return questions;
    }

    private void persistAssessment(
            RiskAssessmentRequest request,
            int riskScore,
            String riskTier,
            List<RiskIndicator> indicators,
            List<ContextAnswer> contextAnswers,
            String recommendation,
            int latencyMs) {
        try {
            String inputType = determineInputType(request);
            String rawPayload = extractPayload(request);
            String payloadHash = hashPayload(rawPayload);
            UUID userId = resolveCurrentUserId();

            ScanHistory scanHistory = ScanHistory.builder()
                    .id(UUID.randomUUID())
                    .userId(userId)
                    .inputType(inputType)
                    .payloadHash(payloadHash)
                    .createdAt(Instant.now())
                    .build();

            scanHistory = scanHistoryRepository.save(scanHistory);

            String indicatorsJson = indicators != null ? objectMapper.writeValueAsString(indicators) : "[]";
            String contextAnswersJson = contextAnswers != null ? objectMapper.writeValueAsString(contextAnswers) : null;

            RiskAssessment riskAssessment = RiskAssessment.builder()
                    .id(UUID.randomUUID())
                    .scanId(scanHistory.getId())
                    .riskScore(riskScore)
                    .riskTier(riskTier)
                    .indicatorsJson(indicatorsJson)
                    .contextAnswersJson(contextAnswersJson)
                    .recommendation(recommendation)
                    .latencyMs(latencyMs)
                    .createdAt(Instant.now())
                    .build();

            riskAssessmentRepository.save(riskAssessment);
        } catch (Exception e) {
            log.warn("Could not persist scan history and risk assessment record: {}", e.getMessage());
        }
    }

    private String determineInputType(RiskAssessmentRequest request) {
        if (request.getQrPayload() != null && !request.getQrPayload().isBlank()) {
            return "QR";
        } else if (request.getMessageContent() != null && !request.getMessageContent().isBlank()) {
            return "MSG";
        } else if (request.getUrl() != null && !request.getUrl().isBlank()) {
            return "URL";
        } else {
            return "PAYMENT";
        }
    }

    private String extractPayload(RiskAssessmentRequest request) {
        if (request.getQrPayload() != null && !request.getQrPayload().isBlank()) {
            return request.getQrPayload();
        } else if (request.getMessageContent() != null && !request.getMessageContent().isBlank()) {
            return request.getMessageContent();
        } else if (request.getUrl() != null && !request.getUrl().isBlank()) {
            return request.getUrl();
        } else if (request.getPayeeVpa() != null && !request.getPayeeVpa().isBlank()) {
            return request.getPayeeVpa() + ":" + request.getPaymentAmount();
        } else {
            return "UNKNOWN_PAYLOAD";
        }
    }

    private String hashPayload(String payload) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(payload.hashCode());
        }
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
