package com.upishield.common.util;

import com.upishield.common.exception.BadRequestException;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Utility for detecting and sanitizing sensitive credential patterns (PIN, OTP, CVV, passwords)
 * to comply with Zero Credential Capture policies and prevent credential theft.
 */
@Component
public class CredentialSanitizer {

    public CredentialSanitizer() {
        // public constructor to allow instantiation or injection
    }

    // Matches PIN/OTP patterns like pin=1234, upi_pin:123456, otp=123456, cvv=123, password=xyz
    private static final Pattern SENSITIVE_PATTERNS = Pattern.compile(
            "(?i)(?:\\b(?:upi[_-]?pin|mpin|pin|otp|cvv|cvc|password|pwd|passcode)\\s*[:=]\\s*\\S+)|" +
            "(?:\\b(?:upi[_-]?pin|mpin|pin|otp|cvv|cvc)\\s*[:=]?\\s*\\d{3,8}\\b)|" +
            "(?:[?&](?:upi[_-]?pin|mpin|pin|otp|cvv|cvc|password)=)",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Checks whether the given text contains sensitive credential patterns such as PINs or OTPs.
     *
     * @param text input string to inspect
     * @return true if sensitive credential pattern is detected, false otherwise
     */
    public static boolean containsCredentials(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }
        return SENSITIVE_PATTERNS.matcher(text).find();
    }

    public boolean hasCredentials(String text) {
        return containsCredentials(text);
    }

    /**
     * Validates that the input text does not contain sensitive credentials.
     * Throws {@link BadRequestException} if credential patterns are found.
     *
     * @param text input string to validate
     * @throws BadRequestException if credentials are found
     */
    public static void validateNoCredentials(String text) {
        if (containsCredentials(text)) {
            throw new BadRequestException("Payload contains sensitive credential patterns (PIN/OTP). Credentials must never be transmitted or scanned.");
        }
    }

    public void check(String text) {
        validateNoCredentials(text);
    }

    /**
     * Sanitizes any sensitive credential values in the input text by replacing them with [REDACTED].
     *
     * @param text input string
     * @return sanitized string
     */
    public static String sanitize(String text) {
        if (text == null || text.isBlank()) {
            return text;
        }
        return SENSITIVE_PATTERNS.matcher(text).replaceAll("[REDACTED_CREDENTIAL]");
    }

    public String sanitizeInput(String text) {
        return sanitize(text);
    }
}
