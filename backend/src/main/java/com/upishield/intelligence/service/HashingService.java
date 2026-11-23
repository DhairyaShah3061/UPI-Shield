package com.upishield.intelligence.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;

@Service
@Slf4j
public class HashingService {

    private static final String HMAC_SHA256 = "HmacSHA256";

    private final String secretKey;

    public HashingService(@Value("${app.hashing.secret:default-secret-key-for-hmac-sha256-upishield-secure}") String secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * Compute HMAC-SHA256 hash using the server-managed secret key.
     *
     * @param input the input string to hash
     * @return 64-character lowercase hex encoded string
     */
    public String hmacHash(String input) {
        if (input == null) {
            return null;
        }
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), HMAC_SHA256);
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hmacBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            log.error("Failed to compute HMAC-SHA256 for input", e);
            throw new IllegalStateException("Cryptographic algorithm error computing HMAC-SHA256", e);
        }
    }

    /**
     * Normalize the input (trim and lowercase) and compute HMAC-SHA256.
     *
     * @param input raw input string (e.g. VPA, phone, domain)
     * @return 64-character lowercase hex hash
     */
    public String normalizeAndHash(String input) {
        if (input == null) {
            return null;
        }
        String normalized = input.trim().toLowerCase(Locale.ROOT);
        return hmacHash(normalized);
    }

    /**
     * Mask sensitive indicator values for safe display.
     * Examples:
     * - VPA: "abc***@upi"
     * - Phone: "98****1234"
     * - Domain: "ex****le.com"
     * - QR_HASH / other: "a1b2****c3d4"
     *
     * @param input the raw value to mask
     * @param type the indicator type (VPA, PHONE, DOMAIN, QR_HASH)
     * @return masked display string
     */
    public String maskForDisplay(String input, String type) {
        if (input == null || input.isBlank()) {
            return "";
        }
        String trimmed = input.trim();
        String normalizedType = type != null ? type.trim().toUpperCase(Locale.ROOT) : "";

        return switch (normalizedType) {
            case "VPA" -> maskVpa(trimmed);
            case "PHONE" -> maskPhone(trimmed);
            case "DOMAIN" -> maskDomain(trimmed);
            default -> maskGeneric(trimmed);
        };
    }

    private String maskVpa(String vpa) {
        int atIndex = vpa.indexOf('@');
        if (atIndex > 0) {
            String handle = vpa.substring(0, atIndex);
            String provider = vpa.substring(atIndex); // includes '@'
            if (handle.length() <= 3) {
                return handle.charAt(0) + "***" + provider;
            }
            return handle.substring(0, 3) + "***" + provider;
        }
        if (vpa.length() <= 3) {
            return vpa.charAt(0) + "***";
        }
        return vpa.substring(0, 3) + "***";
    }

    private String maskPhone(String phone) {
        // Strip out non-digit characters for masking if desired, or preserve
        String digitsOnly = phone.replaceAll("[^0-9]", "");
        if (digitsOnly.length() >= 10) {
            String prefix = digitsOnly.substring(0, 2);
            String suffix = digitsOnly.substring(digitsOnly.length() - 4);
            return prefix + "****" + suffix;
        }
        if (phone.length() >= 6) {
            return phone.substring(0, 2) + "****" + phone.substring(phone.length() - 2);
        }
        return "****";
    }

    private String maskDomain(String domain) {
        int dotIndex = domain.lastIndexOf('.');
        if (dotIndex > 2) {
            String host = domain.substring(0, dotIndex);
            String tld = domain.substring(dotIndex);
            if (host.length() <= 3) {
                return host.charAt(0) + "****" + tld;
            }
            return host.substring(0, 2) + "****" + host.substring(host.length() - 2) + tld;
        }
        if (domain.length() >= 4) {
            return domain.substring(0, 2) + "****" + domain.substring(domain.length() - 2);
        }
        return "****";
    }

    private String maskGeneric(String value) {
        if (value.length() <= 6) {
            return "****";
        }
        int keep = Math.min(4, value.length() / 3);
        return value.substring(0, keep) + "****" + value.substring(value.length() - keep);
    }
}
