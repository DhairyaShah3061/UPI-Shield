package com.upishield.scanner.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Extracted parameters from a UPI payment URI (upi://pay?...).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpiPaymentDetails {

    private String payeeVpa;
    private String payeeName;
    private String amount;
    private String currency;
    private String transactionNote;
    private String merchantCode;
    private String transactionRef;

    /**
     * True indicates money goes OUT of the user's account (payment request).
     */
    private boolean isPaymentRequest;
}
