package com.upishield.android;

import java.util.List;

public class MessageAnalysisResponse {
    public String originalContent;
    public List<String> extractedUrls;
    public List<String> extractedVpas;
    public List<String> extractedPhoneNumbers;
    public List<String> extractedAmounts;
    public List<SocialEngineeringSignal> signals;
    public int signalCount;
    public boolean remoteAppDetected;
    public boolean pinRequestDetected;
    public boolean urgencyDetected;
    public boolean threatDetected;
}
