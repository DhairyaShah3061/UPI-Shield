package com.upishield.analyzer.service;

import com.upishield.analyzer.dto.ContentExtractionResult;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ContentExtractor {

    // Regex for HTTP / HTTPS URLs, excluding trailing punctuation
    private static final Pattern URL_PATTERN = Pattern.compile(
            "\\bhttps?://[a-zA-Z0-9.-]+(?:\\.[a-zA-Z]{2,})?(?::\\d{1,5})?(?:/[^\\s\"'<>)\\]]*)?",
            Pattern.CASE_INSENSITIVE
    );

    // Regex for UPI VPA (word@word pattern: handle@provider)
    private static final Pattern VPA_PATTERN = Pattern.compile(
            "\\b([a-zA-Z0-9._-]+@[a-zA-Z0-9]+(?:\\.[a-zA-Z0-9]+)?)\\b",
            Pattern.CASE_INSENSITIVE
    );

    // Common standard email domains that should not be classified as UPI VPAs
    private static final Set<String> EXCLUDED_EMAIL_DOMAINS = Set.of(
            "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
            "protonmail.com", "mail.com", "zoho.com", "yandex.com"
    );

    // Regex for Indian phone numbers (+91, 0, or 10-digit starting with 6-9)
    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "(?<!\\d)(?:(?:\\+91|91|0)[\\s-]?)?([6-9]\\d{9})(?!\\d)|" +
            "(?<!\\d)(?:(?:\\+91|91|0)[\\s-]?)?([6-9]\\d{4}[\\s-]\\d{5})(?!\\d)|" +
            "(?<!\\d)(?:(?:\\+91|91|0)[\\s-]?)?([6-9]\\d{2}[\\s-]\\d{3}[\\s-]\\d{4})(?!\\d)"
    );

    // Regex for Indian currency amounts (₹, Rs., INR, rupees)
    private static final Pattern AMOUNT_PATTERN = Pattern.compile(
            "(?:₹|Rs\\.?|INR)\\s*(\\d+(?:,\\d+)*(?:\\.\\d{1,2})?)|" +
            "\\b(\\d+(?:,\\d+)*(?:\\.\\d{1,2})?)\\s*(?:₹|Rs\\.?|INR|rupees?|rupaye)\\b",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Extracts all HTTP/HTTPS URLs from text.
     *
     * @param text input string
     * @return list of distinct URLs
     */
    public List<String> extractUrls(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }

        Set<String> urls = new LinkedHashSet<>();
        Matcher matcher = URL_PATTERN.matcher(text);
        while (matcher.find()) {
            String url = matcher.group();
            // Clean any trailing punctuation attached to sentence ends
            url = cleanTrailingPunctuation(url);
            if (!url.isBlank()) {
                urls.add(url);
            }
        }
        return new ArrayList<>(urls);
    }

    /**
     * Extracts UPI Virtual Payment Addresses (VPAs) from text matching word@word pattern.
     *
     * @param text input string
     * @return list of distinct VPAs
     */
    public List<String> extractVpas(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }

        Set<String> vpas = new LinkedHashSet<>();
        Matcher matcher = VPA_PATTERN.matcher(text);
        while (matcher.find()) {
            String vpa = matcher.group(1);
            if (isValidVpa(vpa)) {
                vpas.add(vpa.toLowerCase());
            }
        }
        return new ArrayList<>(vpas);
    }

    /**
     * Extracts Indian phone numbers (+91 or 10-digit mobile) from text.
     *
     * @param text input string
     * @return list of distinct phone numbers
     */
    public List<String> extractPhoneNumbers(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }

        Set<String> phoneNumbers = new LinkedHashSet<>();
        Matcher matcher = PHONE_PATTERN.matcher(text);
        while (matcher.find()) {
            String matched = matcher.group();
            if (matched != null && !matched.isBlank()) {
                phoneNumbers.add(matched.trim());
            }
        }
        return new ArrayList<>(phoneNumbers);
    }

    /**
     * Extracts currency amounts (₹, Rs, INR patterns) from text.
     *
     * @param text input string
     * @return list of distinct formatted amount strings
     */
    public List<String> extractAmounts(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }

        Set<String> amounts = new LinkedHashSet<>();
        Matcher matcher = AMOUNT_PATTERN.matcher(text);
        while (matcher.find()) {
            String matched = matcher.group();
            if (matched != null && !matched.isBlank()) {
                amounts.add(cleanTrailingPunctuation(matched.trim()));
            }
        }
        return new ArrayList<>(amounts);
    }

    /**
     * Extracts URLs, VPAs, phone numbers, and amounts from text.
     *
     * @param text input string
     * @return ContentExtractionResult containing all extracted entities
     */
    public ContentExtractionResult extractAll(String text) {
        return ContentExtractionResult.builder()
                .urls(extractUrls(text))
                .vpas(extractVpas(text))
                .phoneNumbers(extractPhoneNumbers(text))
                .amounts(extractAmounts(text))
                .build();
    }

    private boolean isValidVpa(String vpa) {
        if (vpa == null || !vpa.contains("@")) {
            return false;
        }
        String[] parts = vpa.split("@", 2);
        String handle = parts[0];
        String provider = parts[1].toLowerCase();

        if (handle.isBlank() || provider.isBlank()) {
            return false;
        }
        // Exclude standard public email providers
        return !EXCLUDED_EMAIL_DOMAINS.contains(provider);
    }

    private String cleanTrailingPunctuation(String input) {
        if (input == null) {
            return "";
        }
        while (input.length() > 0) {
            char last = input.charAt(input.length() - 1);
            if (last == '.' || last == ',' || last == ';' || last == '!' || last == '?' || last == ':' || last == ')' || last == ']') {
                input = input.substring(0, input.length() - 1);
            } else {
                break;
            }
        }
        return input;
    }
}
