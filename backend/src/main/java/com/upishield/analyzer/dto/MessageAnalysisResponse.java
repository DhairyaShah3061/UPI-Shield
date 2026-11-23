package com.upishield.analyzer.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MessageAnalysisResponse {

    private String originalContent;

    @Builder.Default
    private List<String> extractedUrls = new ArrayList<>();

    @Builder.Default
    private List<String> extractedVpas = new ArrayList<>();

    @Builder.Default
    private List<String> extractedPhoneNumbers = new ArrayList<>();

    @Builder.Default
    private List<String> extractedAmounts = new ArrayList<>();

    @Builder.Default
    private List<SocialEngineeringSignal> signals = new ArrayList<>();

    private int signalCount;

    public int getSignalCount() {
        if (signals != null) {
            return signals.size();
        }
        return signalCount;
    }

    public boolean isRemoteAppDetected() {
        return signals != null && signals.stream()
                .anyMatch(s -> "REMOTE_ACCESS".equalsIgnoreCase(s.getSignalType())
                        || "APK_INSTALL".equalsIgnoreCase(s.getSignalType())
                        || "REMOTE_ACCESS_APP".equalsIgnoreCase(s.getSignalType()));
    }

    public boolean isPinRequestDetected() {
        return signals != null && signals.stream()
                .anyMatch(s -> "PIN_FOR_RECEIVE".equalsIgnoreCase(s.getSignalType())
                        || "PIN_TO_RECEIVE".equalsIgnoreCase(s.getSignalType()));
    }

    public boolean isUrgencyDetected() {
        return signals != null && signals.stream()
                .anyMatch(s -> "URGENCY_THREAT".equalsIgnoreCase(s.getSignalType())
                        || "ARTIFICIAL_URGENCY".equalsIgnoreCase(s.getSignalType()));
    }

    public boolean isThreatDetected() {
        return isUrgencyDetected();
    }

    public List<String> getExtractedPhones() {
        return extractedPhoneNumbers != null ? extractedPhoneNumbers : List.of();
    }
}
