package com.upishield.analyzer.service;

import com.upishield.analyzer.dto.ContentExtractionResult;
import com.upishield.analyzer.dto.MessageAnalysisResponse;
import com.upishield.analyzer.dto.SocialEngineeringSignal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class MessageAnalyzer {

    private final ContentExtractor contentExtractor;

    private static final List<SignalDefinition> SIGNAL_DEFINITIONS = List.of(
            // a. URGENCY_THREAT
            new SignalDefinition(
                    "URGENCY_THREAT",
                    "Threat or artificial urgency to pressure user into acting without thinking",
                    List.of(
                            new PatternRule("(?i)\\baccount\\s+blocked\\b", "STRONG"),
                            new PatternRule("(?i)\\belectricity\\s+disconnection\\b", "STRONG"),
                            new PatternRule("(?i)\\blast\\s+warning\\b", "STRONG"),
                            new PatternRule("(?i)\\bwithin\\s+24\\s+hours\\b", "MODERATE"),
                            new PatternRule("(?i)\\bimmediately\\b", "MODERATE"),
                            new PatternRule("(?i)\\baccount\\s+suspended\\b", "STRONG"),
                            new PatternRule("(?i)\\baction\\s+required\\s+immediately\\b", "STRONG")
                    )
            ),

            // b. PIN_FOR_RECEIVE
            new SignalDefinition(
                    "PIN_FOR_RECEIVE",
                    "Request to enter UPI PIN or MPIN to receive money or refund (UPI PIN is debit-only)",
                    List.of(
                            new PatternRule("(?i)\\benter\\s+pin\\s+to\\s+receive\\b", "STRONG"),
                            new PatternRule("(?i)\\bpin\\s+for\\s+refund\\b", "STRONG"),
                            new PatternRule("(?i)\\benter\\s+mpin\\b", "STRONG"),
                            new PatternRule("(?i)\\benter\\s+(?:upi\\s+)?pin\\b", "STRONG"),
                            new PatternRule("(?i)\\bshare\\s+(?:upi\\s+)?pin\\b", "STRONG")
                    )
            ),

            // c. IMPERSONATION
            new SignalDefinition(
                    "IMPERSONATION",
                    "Impersonation of bank personnel, regulatory officials, or customer support",
                    List.of(
                            new PatternRule("(?i)\\bbank\\s+manager\\b", "STRONG"),
                            new PatternRule("(?i)\\brbi\\s+officer\\b", "STRONG"),
                            new PatternRule("(?i)\\bcustomer\\s+care\\b", "MODERATE"),
                            new PatternRule("(?i)\\bkyc\\s+update\\s+required\\b", "MODERATE"),
                            new PatternRule("(?i)\\bincome\\s+tax\\s+officer\\b", "STRONG"),
                            new PatternRule("(?i)\\bpolice\\s+department\\b", "STRONG")
                    )
            ),

            // d. REMOTE_ACCESS
            new SignalDefinition(
                    "REMOTE_ACCESS",
                    "Request to install remote desktop/screen sharing app to take control of user device",
                    List.of(
                            new PatternRule("(?i)\\binstall\\s+anydesk\\b", "STRONG"),
                            new PatternRule("(?i)\\bteamviewer\\b", "STRONG"),
                            new PatternRule("(?i)\\bscreen\\s+sharing\\b", "STRONG"),
                            new PatternRule("(?i)\\bquicksupport\\b", "STRONG"),
                            new PatternRule("(?i)\\banydesk\\b", "STRONG"),
                            new PatternRule("(?i)\\brustdesk\\b", "STRONG"),
                            new PatternRule("(?i)\\bultraviewer\\b", "STRONG")
                    )
            ),

            // e. VERIFICATION_FEE
            new SignalDefinition(
                    "VERIFICATION_FEE",
                    "Advance fee scam requesting small charge or verification amount before releasing funds",
                    List.of(
                            new PatternRule("(?i)\\bsmall\\s+fee\\b", "MODERATE"),
                            new PatternRule("(?i)\\bprocessing\\s+charge\\b", "MODERATE"),
                            new PatternRule("(?i)\\bverification\\s+amount\\b", "MODERATE"),
                            new PatternRule("(?i)\\bregistration\\s+fee\\b", "MODERATE"),
                            new PatternRule("(?i)\\brefundable\\s+charge\\b", "MODERATE")
                    )
            ),

            // f. APK_INSTALL
            new SignalDefinition(
                    "APK_INSTALL",
                    "Prompting manual download or sideloading of an unverified APK application",
                    List.of(
                            new PatternRule("(?i)\\bdownload\\s+this\\s+app\\b", "STRONG"),
                            new PatternRule("(?i)\\binstall\\s+apk\\b", "STRONG"),
                            new PatternRule("(?i)\\bclick\\s+to\\s+install\\b", "STRONG"),
                            new PatternRule("(?i)\\bdownload\\s+apk\\b", "STRONG"),
                            new PatternRule("(?i)\\.apk\\b", "STRONG")
                    )
            )
    );

    /**
     * Analyzes message content for social engineering indicators and extracts embedded entities.
     *
     * @param content message text to analyze
     * @return MessageAnalysisResponse
     */
    public MessageAnalysisResponse analyzeMessage(String content) {
        if (content == null || content.isBlank()) {
            return MessageAnalysisResponse.builder()
                    .extractedUrls(new ArrayList<>())
                    .extractedVpas(new ArrayList<>())
                    .extractedPhoneNumbers(new ArrayList<>())
                    .extractedAmounts(new ArrayList<>())
                    .signals(new ArrayList<>())
                    .signalCount(0)
                    .build();
        }

        // 1. Extract embedded entities using ContentExtractor
        ContentExtractionResult entities = contentExtractor.extractAll(content);

        // 2. Detect social engineering signals using pattern matching
        List<SocialEngineeringSignal> detectedSignals = new ArrayList<>();

        for (SignalDefinition definition : SIGNAL_DEFINITIONS) {
            for (PatternRule rule : definition.rules()) {
                Matcher matcher = rule.pattern().matcher(content);
                while (matcher.find()) {
                    String matchedText = matcher.group();
                    // Avoid duplicate identical matches for the same rule
                    boolean alreadyPresent = detectedSignals.stream()
                            .anyMatch(s -> s.getSignalType().equals(definition.signalType())
                                    && s.getMatchedText().equalsIgnoreCase(matchedText));

                    if (!alreadyPresent) {
                        detectedSignals.add(SocialEngineeringSignal.builder()
                                .signalType(definition.signalType())
                                .description(definition.description())
                                .matchedText(matchedText)
                                .severity(rule.severity())
                                .build());
                    }
                }
            }
        }

        return MessageAnalysisResponse.builder()
                .originalContent(content)
                .extractedUrls(entities.getUrls())
                .extractedVpas(entities.getVpas())
                .extractedPhoneNumbers(entities.getPhoneNumbers())
                .extractedAmounts(entities.getAmounts())
                .signals(detectedSignals)
                .signalCount(detectedSignals.size())
                .build();
    }

    /**
     * Legacy convenience method delegating to analyzeMessage.
     *
     * @param messageContent content to analyze
     * @return MessageAnalysisResponse
     */
    public MessageAnalysisResponse analyze(String messageContent) {
        return analyzeMessage(messageContent);
    }

    private record PatternRule(Pattern pattern, String severity) {
        PatternRule(String regex, String severity) {
            this(Pattern.compile(regex), severity);
        }
    }

    private record SignalDefinition(
            String signalType,
            String description,
            List<PatternRule> rules
    ) {}
}
