package com.upishield.scanner.controller;

import com.upishield.common.dto.ApiResponse;
import com.upishield.common.util.CredentialSanitizer;
import com.upishield.scanner.dto.QRScanRequest;
import com.upishield.scanner.dto.QRScanResponse;
import com.upishield.scanner.service.QRDecoder;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller exposing endpoints for QR code scanning, decoding,
 * and anomaly inspection.
 */
@RestController
@RequestMapping("/api/v1/scan")
@RequiredArgsConstructor
public class QRController {

    private final QRDecoder qrDecoder;

    /**
     * Scans a raw QR payload, determines its type, evaluates anomalies,
     * and returns safety guidance.
     *
     * @param request QR scan request containing rawPayload
     * @return decoded QRScanResponse wrapped in ApiResponse
     */
    @PostMapping("/qr")
    public ResponseEntity<ApiResponse<QRScanResponse>> scanQr(@Valid @RequestBody QRScanRequest request) {
        CredentialSanitizer.validateNoCredentials(request.getRawPayload());
        QRScanResponse response = qrDecoder.decodePayload(request.getRawPayload());
        return ResponseEntity.ok(ApiResponse.success(response));
    }
}
