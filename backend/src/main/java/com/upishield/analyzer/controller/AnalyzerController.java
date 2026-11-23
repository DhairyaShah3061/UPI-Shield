package com.upishield.analyzer.controller;

import com.upishield.analyzer.dto.MessageAnalysisRequest;
import com.upishield.analyzer.dto.MessageAnalysisResponse;
import com.upishield.analyzer.dto.UrlAnalysisRequest;
import com.upishield.analyzer.dto.UrlAnalysisResponse;
import com.upishield.analyzer.service.MessageAnalyzer;
import com.upishield.analyzer.service.URLAnalyzer;
import com.upishield.common.dto.ApiResponse;
import com.upishield.common.util.CredentialSanitizer;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/analyze")
@RequiredArgsConstructor
public class AnalyzerController {

    private final MessageAnalyzer messageAnalyzer;
    private final URLAnalyzer urlAnalyzer;

    @PostMapping("/message")
    public ResponseEntity<ApiResponse<MessageAnalysisResponse>> analyzeMessage(
            @Valid @RequestBody MessageAnalysisRequest request
    ) {
        CredentialSanitizer.validateNoCredentials(request.getContent());
        MessageAnalysisResponse response = messageAnalyzer.analyzeMessage(request.getContent());
        return ResponseEntity.ok(ApiResponse.success("Message analyzed successfully", response));
    }

    @PostMapping("/url")
    public ResponseEntity<ApiResponse<UrlAnalysisResponse>> analyzeUrl(
            @Valid @RequestBody UrlAnalysisRequest request
    ) {
        CredentialSanitizer.validateNoCredentials(request.getUrl());
        UrlAnalysisResponse response = urlAnalyzer.analyzeUrl(request.getUrl());
        return ResponseEntity.ok(ApiResponse.success("URL analyzed successfully", response));
    }
}
