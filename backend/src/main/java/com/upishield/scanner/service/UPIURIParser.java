package com.upishield.scanner.service;

import com.upishield.common.exception.BadRequestException;
import com.upishield.scanner.dto.UpiPaymentDetails;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Service responsible for parsing standard NPCI UPI payment URIs (upi://pay?...)
 * and validating mandatory attributes such as Payee VPA and transaction amounts.
 */
@Service
public class UPIURIParser {

    private static final String UPI_SCHEME_PREFIX = "upi://pay";
    private static final String DEFAULT_CURRENCY = "INR";

    /**
     * Parses a raw UPI URI string and extracts payment details.
     * Validates that the payee VPA contains '@' and any specified amount is numeric and non-negative.
     *
     * @param uri the raw UPI URI (e.g. upi://pay?pa=...&pn=...&am=...)
     * @return populated {@link UpiPaymentDetails} with isPaymentRequest=true
     * @throws BadRequestException if the URI is null, does not start with upi://pay,
     *                             has an invalid VPA format, or has an invalid amount
     */
    public UpiPaymentDetails parseUpiUri(String uri) {
        if (uri == null || uri.isBlank()) {
            throw new BadRequestException("UPI URI must not be null or blank");
        }

        String trimmed = uri.trim();
        if (!trimmed.toLowerCase().startsWith(UPI_SCHEME_PREFIX)) {
            throw new BadRequestException("Invalid UPI URI scheme: must start with " + UPI_SCHEME_PREFIX);
        }

        Map<String, String> params = extractParameters(trimmed);

        String payeeVpa = params.get("pa");
        validateVpa(payeeVpa);

        String amount = params.get("am");
        if (amount != null && !amount.isBlank()) {
            validateAmount(amount);
        }

        String currency = params.get("cu");
        if (currency == null || currency.isBlank()) {
            currency = DEFAULT_CURRENCY;
        }

        return UpiPaymentDetails.builder()
                .payeeVpa(payeeVpa)
                .payeeName(params.get("pn"))
                .amount(amount)
                .currency(currency)
                .transactionNote(params.get("tn"))
                .merchantCode(params.get("mc"))
                .transactionRef(params.get("tr"))
                .isPaymentRequest(true)
                .build();
    }

    /**
     * Extracts query parameters from a UPI URI into a key-value Map.
     * URL decodes keys and values using UTF-8.
     *
     * @param uri raw UPI URI
     * @return map of parameter names to decoded values (in order of appearance)
     */
    public Map<String, String> extractParameters(String uri) {
        if (uri == null || uri.isBlank()) {
            return Collections.emptyMap();
        }

        int queryIndex = uri.indexOf('?');
        if (queryIndex < 0 || queryIndex >= uri.length() - 1) {
            return Collections.emptyMap();
        }

        String queryString = uri.substring(queryIndex + 1);
        // Replace XML escaped &amp; if present
        queryString = queryString.replace("&amp;", "&");

        Map<String, String> params = new LinkedHashMap<>();
        String[] pairs = queryString.split("&");

        for (String pair : pairs) {
            if (pair.isBlank()) {
                continue;
            }
            int eqIndex = pair.indexOf('=');
            if (eqIndex > 0) {
                String rawKey = pair.substring(0, eqIndex);
                String rawValue = pair.substring(eqIndex + 1);
                try {
                    String decodedKey = URLDecoder.decode(rawKey.trim(), StandardCharsets.UTF_8);
                    String decodedValue = URLDecoder.decode(rawValue.trim(), StandardCharsets.UTF_8);
                    params.put(decodedKey, decodedValue);
                } catch (Exception e) {
                    params.put(rawKey.trim(), rawValue.trim());
                }
            } else if (eqIndex < 0) {
                try {
                    String decodedKey = URLDecoder.decode(pair.trim(), StandardCharsets.UTF_8);
                    params.put(decodedKey, "");
                } catch (Exception e) {
                    params.put(pair.trim(), "");
                }
            }
        }

        return params;
    }

    /**
     * Validates that the VPA format contains '@' and has valid username and provider handle components.
     *
     * @param vpa Virtual Payment Address (e.g. user@okhdfcbank)
     * @throws BadRequestException if the VPA is invalid
     */
    public void validateVpa(String vpa) {
        if (!isValidVpa(vpa)) {
            throw new BadRequestException("Invalid VPA format: Payee VPA must contain '@' (" + (vpa == null ? "missing" : vpa) + ")");
        }
    }

    /**
     * Checks if the VPA is non-empty, contains '@', and has characters before and after '@'.
     *
     * @param vpa Virtual Payment Address
     * @return true if valid, false otherwise
     */
    public boolean isValidVpa(String vpa) {
        if (vpa == null || vpa.isBlank()) {
            return false;
        }
        int atIndex = vpa.indexOf('@');
        return atIndex > 0 && atIndex < vpa.length() - 1 && vpa.indexOf('@', atIndex + 1) == -1;
    }

    /**
     * Validates that the amount is numeric and non-negative.
     *
     * @param amount amount string
     * @throws BadRequestException if amount is non-numeric or negative
     */
    public void validateAmount(String amount) {
        if (!isValidAmount(amount)) {
            throw new BadRequestException("Invalid amount: Amount must be numeric and non-negative (" + amount + ")");
        }
    }

    /**
     * Checks if the amount string represents a valid non-negative number.
     *
     * @param amount amount string
     * @return true if valid number and >= 0, false otherwise
     */
    public boolean isValidAmount(String amount) {
        if (amount == null || amount.isBlank()) {
            return false;
        }
        try {
            BigDecimal val = new BigDecimal(amount.trim());
            return val.compareTo(BigDecimal.ZERO) >= 0;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
