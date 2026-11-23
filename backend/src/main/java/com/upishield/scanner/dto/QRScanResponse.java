package com.upishield.scanner.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * Response payload returned after decoding and analyzing a QR code.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class QRScanResponse {

    private String rawPayload;

    /**
     * Payload type: UPI_PAY, URL, TEXT, UNKNOWN
     */
    private String payloadType;

    /**
     * UPI payment details if payloadType is UPI_PAY, null otherwise
     */
    private UpiPaymentDetails upiDetails;

    /**
     * List of identified anomalies or suspicious attributes
     */
    @Builder.Default
    private List<String> anomalies = new ArrayList<>();

    /**
     * Safety and operation guidance (e.g. clarifying payment vs receiving money)
     */
    private String operationClarification;

    /**
     * Whether completing this operation requires entering a UPI PIN (true = money sent)
     */
    private boolean requiresPin;

    /**
     * SHA-256 hash of the raw payload for threat indicator lookups
     */
    private String payloadHash;

    /**
     * Whether the QR payload claims PIN is required to receive funds
     */
    private boolean claimsPinToReceive;

    public boolean isClaimsPinToReceive() {
        return claimsPinToReceive;
    }

    /**
     * Alias getter for upiDetails to support consumers expecting getPaymentDetails()
     */
    public UpiPaymentDetails getPaymentDetails() {
        return upiDetails;
    }

    /**
     * Alias setter for upiDetails
     */
    public void setPaymentDetails(UpiPaymentDetails paymentDetails) {
        this.upiDetails = paymentDetails;
    }
}
