package com.upishield.scanner.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request payload containing the raw string scanned from a QR code.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class QRScanRequest {

    @NotBlank(message = "Raw QR payload must not be blank")
    private String rawPayload;
}
