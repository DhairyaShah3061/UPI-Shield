package com.upishield.analyzer.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
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
public class UrlAnalysisResponse {

    private String originalUrl;
    private String finalUrl;

    @Builder.Default
    private List<String> redirectChain = new ArrayList<>();

    @JsonProperty("isSuspicious")
    private boolean isSuspicious;

    @Builder.Default
    private List<String> suspiciousReasons = new ArrayList<>();

    private String domainAge;

    @JsonProperty("isLookalikeDomain")
    private boolean isLookalikeDomain;

    public boolean isSuspicious() {
        return isSuspicious;
    }

    public void setSuspicious(boolean suspicious) {
        this.isSuspicious = suspicious;
    }

    public void setIsSuspicious(boolean isSuspicious) {
        this.isSuspicious = isSuspicious;
    }

    public boolean isLookalikeDomain() {
        return isLookalikeDomain;
    }

    public void setLookalikeDomain(boolean lookalikeDomain) {
        this.isLookalikeDomain = lookalikeDomain;
    }

    public void setIsLookalikeDomain(boolean isLookalikeDomain) {
        this.isLookalikeDomain = isLookalikeDomain;
    }

    public boolean isMalicious() {
        return isSuspicious || isLookalikeDomain;
    }

    public boolean isPhishing() {
        return isLookalikeDomain;
    }

    public boolean isSuspiciousDomain() {
        return isLookalikeDomain || isSuspicious;
    }

    public int getThreatScore() {
        if (isLookalikeDomain) return 80;
        if (isSuspicious) return 60;
        return 0;
    }

    public String getThreatDescription() {
        return suspiciousReasons != null && !suspiciousReasons.isEmpty() ? String.join("; ", suspiciousReasons) : null;
    }

    public String getDomain() {
        if (originalUrl == null) return null;
        try {
            java.net.URI uri = new java.net.URI(originalUrl.startsWith("http") ? originalUrl : "http://" + originalUrl);
            return uri.getHost();
        } catch (Exception e) {
            return null;
        }
    }
}
