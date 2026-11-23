package com.upishield.scanner.service;

import com.upishield.common.exception.BadRequestException;
import com.upishield.common.util.CredentialSanitizer;
import com.upishield.scanner.dto.QRScanResponse;
import com.upishield.scanner.dto.UpiPaymentDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Service for decoding raw QR payloads, classifying their payload type
 * (UPI_PAY, URL, TEXT, UNKNOWN), detecting security anomalies, and providing
 * NPCI-aligned operation guidance.
 */
@Service
@RequiredArgsConstructor
public class QRDecoder {

    private final UPIURIParser upiUriParser;

    public static final String UPI_PAY_CLARIFICATION =
            "This QR code requests a PAYMENT. Entering your UPI PIN will SEND money. A PIN is never needed to receive money.";

    private static final String PAYLOAD_TYPE_UPI_PAY = "UPI_PAY";
    private static final String PAYLOAD_TYPE_URL = "URL";
    private static final String PAYLOAD_TYPE_TEXT = "TEXT";
    private static final String PAYLOAD_TYPE_UNKNOWN = "UNKNOWN";

    private static final BigDecimal HIGH_AMOUNT_THRESHOLD = new BigDecimal("10000");

    // Recognised standard UPI specification parameters
    private static final Set<String> STANDARD_UPI_PARAMS = Set.of(
            "pa", "pn", "mc", "tid", "tr", "tn", "am", "mam", "cu",
            "url", "mode", "orgid", "mid", "msid", "mtid", "sign",
            "qrts", "link", "invoice", "tier", "refid"
    );

    // Keywords associated with refund or prize scams
    private static final List<String> REFUND_PRIZE_KEYWORDS = List.of(
            "refund", "prize", "cashback", "reward", "lottery",
            "winner", "won", "congratulations", "bonus", "claim",
            "gift", "kyc", "verification", "reversal", "compensation"
    );

    // Pattern to identify embedded URLs within strings
    private static final Pattern EMBEDDED_URL_PATTERN = Pattern.compile(
            "(?i)(https?://\\S+|www\\.\\S+|[a-zA-Z0-9-]+\\.(?:com|org|net|in|co|xyz|top|live|info|app|biz|tk|ml|ga|cf|gq)/?\\S*|\\b(?:bit\\.ly|tinyurl\\.com|t\\.co|is\\.gd)/\\S*)"
    );

    /**
     * Decodes and inspects a raw QR payload.
     * Rejects payloads containing credentials (PINs/OTPs).
     *
     * @param rawPayload raw string from the QR code
     * @return decoded {@link QRScanResponse} with classification and anomaly analysis
     */
    public QRScanResponse decodePayload(String rawPayload) {
        if (rawPayload == null || rawPayload.isBlank()) {
            throw new BadRequestException("Raw QR payload must not be null or blank");
        }

        // Zero Credential Capture: reject payloads with PINs or OTPs
        CredentialSanitizer.validateNoCredentials(rawPayload);

        String trimmed = rawPayload.trim();
        String lower = trimmed.toLowerCase();

        if (lower.startsWith("upi://pay")) {
            return decodeUpiPayload(trimmed, rawPayload);
        } else if (lower.startsWith("http://") || lower.startsWith("https://")) {
            return decodeUrlPayload(trimmed, rawPayload);
        } else {
            return decodeTextOrUnknownPayload(trimmed, rawPayload);
        }
    }

    public QRScanResponse decode(String rawPayload) {
        return decodePayload(rawPayload);
    }

    private QRScanResponse decodeUpiPayload(String trimmed, String rawPayload) {
        List<String> anomalies = new ArrayList<>();
        Map<String, String> params = upiUriParser.extractParameters(trimmed);

        // 1. Check for non-standard parameters
        for (String paramKey : params.keySet()) {
            if (!STANDARD_UPI_PARAMS.contains(paramKey.toLowerCase())) {
                anomalies.add("Non-standard parameter detected: " + paramKey);
            }
        }

        // 2. Check for malformed VPA
        String payeeVpa = params.get("pa");
        if (payeeVpa == null || payeeVpa.isBlank()) {
            anomalies.add("Malformed VPA: Payee VPA parameter 'pa' is missing");
        } else if (!upiUriParser.isValidVpa(payeeVpa)) {
            anomalies.add("Malformed VPA: '" + payeeVpa + "' does not contain valid '@' format");
        }

        // 3. Check for embedded URLs in note field (tn)
        String transactionNote = params.get("tn");
        if (transactionNote != null && containsUrl(transactionNote)) {
            anomalies.add("Embedded URL detected in transaction note: " + transactionNote);
        }

        // 4. Check for pre-filled high amounts (>10000) with refund/prize context in tn
        String amountStr = params.get("am");
        if (amountStr != null && !amountStr.isBlank()) {
            try {
                BigDecimal amountVal = new BigDecimal(amountStr.trim());
                if (amountVal.compareTo(BigDecimal.ZERO) < 0) {
                    anomalies.add("Negative amount detected: " + amountStr);
                } else if (amountVal.compareTo(HIGH_AMOUNT_THRESHOLD) > 0 && hasRefundOrPrizeContext(transactionNote)) {
                    anomalies.add("Suspicious pre-filled high amount (" + amountStr + ") with refund/prize context in note: '" + transactionNote + "'");
                }
            } catch (NumberFormatException e) {
                anomalies.add("Malformed amount parameter (non-numeric): " + amountStr);
            }
        }

        // Attempt strict parsing with UPIURIParser
        UpiPaymentDetails upiDetails;
        try {
            upiDetails = upiUriParser.parseUpiUri(trimmed);
        } catch (BadRequestException ex) {
            String errorMsg = ex.getMessage();
            boolean alreadyPresent = anomalies.stream().anyMatch(a -> a.contains(errorMsg));
            if (!alreadyPresent) {
                anomalies.add("UPI URI validation error: " + errorMsg);
            }
            // Populate UpiPaymentDetails from extracted params so caller still receives parsed info
            upiDetails = UpiPaymentDetails.builder()
                    .payeeVpa(payeeVpa)
                    .payeeName(params.get("pn"))
                    .amount(amountStr)
                    .currency(params.getOrDefault("cu", "INR"))
                    .transactionNote(transactionNote)
                    .merchantCode(params.get("mc"))
                    .transactionRef(params.get("tr"))
                    .isPaymentRequest(true)
                    .build();
        }

        return QRScanResponse.builder()
                .rawPayload(rawPayload)
                .payloadType(PAYLOAD_TYPE_UPI_PAY)
                .upiDetails(upiDetails)
                .anomalies(anomalies)
                .operationClarification(UPI_PAY_CLARIFICATION)
                .requiresPin(true)
                .payloadHash(computeSha256(rawPayload))
                .build();
    }

    private QRScanResponse decodeUrlPayload(String trimmed, String rawPayload) {
        List<String> anomalies = new ArrayList<>();
        if (trimmed.toLowerCase().startsWith("http://")) {
            anomalies.add("Insecure HTTP protocol used instead of HTTPS");
        }

        return QRScanResponse.builder()
                .rawPayload(rawPayload)
                .payloadType(PAYLOAD_TYPE_URL)
                .upiDetails(null)
                .anomalies(anomalies)
                .operationClarification("This QR code opens an external web link. Verify the destination before proceeding.")
                .requiresPin(false)
                .payloadHash(computeSha256(rawPayload))
                .build();
    }

    private QRScanResponse decodeTextOrUnknownPayload(String trimmed, String rawPayload) {
        boolean isPrintableText = isPrintable(trimmed);
        String payloadType = isPrintableText ? PAYLOAD_TYPE_TEXT : PAYLOAD_TYPE_UNKNOWN;

        return QRScanResponse.builder()
                .rawPayload(rawPayload)
                .payloadType(payloadType)
                .upiDetails(null)
                .anomalies(new ArrayList<>())
                .operationClarification("This QR code contains non-payment text data.")
                .requiresPin(false)
                .payloadHash(computeSha256(rawPayload))
                .build();
    }

    private boolean containsUrl(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }
        return EMBEDDED_URL_PATTERN.matcher(text).find();
    }

    private boolean hasRefundOrPrizeContext(String note) {
        if (note == null || note.isBlank()) {
            return false;
        }
        String lowerNote = note.toLowerCase();
        for (String keyword : REFUND_PRIZE_KEYWORDS) {
            if (lowerNote.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private boolean isPrintable(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t') {
                return false;
            }
        }
        return true;
    }

    private String computeSha256(String input) {
        if (input == null) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return null;
        }
    }
}
