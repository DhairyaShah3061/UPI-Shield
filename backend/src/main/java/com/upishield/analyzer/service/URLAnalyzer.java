package com.upishield.analyzer.service;

import com.upishield.analyzer.dto.UrlAnalysisResponse;
import com.upishield.common.exception.BadRequestException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

@Slf4j
@Service
public class URLAnalyzer {

    @Value("${app.url-analyzer.redirect-timeout-ms:3000}")
    private int redirectTimeoutMs = 3000;

    @Value("${app.url-analyzer.max-redirects:5}")
    private int maxRedirects = 5;

    // IP address pattern (IPv4)
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^(\\d{1,3}\\.){3}\\d{1,3}$"
    );

    // Common URL shorteners
    private static final Set<String> URL_SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
            "rb.gy", "shorturl.at", "ow.ly", "goo.gl", "v.gd", "trib.al", "buff.ly"
    );

    // High risk / suspicious top-level domains
    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "cam",
            "work", "icu", "monster", "quest", "live", "fit", "rest", "click", "link"
    );

    // Common scam keywords found in domain labels
    private static final List<String> SCAM_KEYWORDS = List.of(
            "reward", "prize", "lucky", "cashback", "lottery", "winner",
            "offer", "kyc-update", "bonus", "claim", "refund", "free-recharge"
    );

    // Legitimate domains for major UPI / Indian banking services
    private static final List<BrandTarget> TARGET_BRANDS = List.of(
            new BrandTarget("paytm", Set.of("paytm.com")),
            new BrandTarget("phonepe", Set.of("phonepe.com")),
            new BrandTarget("googlepay", Set.of("google.com", "pay.google.com")),
            new BrandTarget("gpay", Set.of("google.com", "pay.google.com")),
            new BrandTarget("sbi", Set.of("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com")),
            new BrandTarget("onlinesbi", Set.of("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com")),
            new BrandTarget("hdfc", Set.of("hdfcbank.com")),
            new BrandTarget("hdfcbank", Set.of("hdfcbank.com")),
            new BrandTarget("icici", Set.of("icicibank.com")),
            new BrandTarget("icicibank", Set.of("icicibank.com")),
            new BrandTarget("axisbank", Set.of("axisbank.com")),
            new BrandTarget("kotak", Set.of("kotak.com")),
            new BrandTarget("bhim", Set.of("bhimupi.org.in", "npci.org.in")),
            new BrandTarget("npci", Set.of("npci.org.in"))
    );

    /**
     * Analyzes a URL for lookalike patterns, SSRF vulnerabilities, suspicious attributes,
     * and traces its redirect chain.
     *
     * @param rawUrl the URL string to inspect
     * @return UrlAnalysisResponse
     */
    public UrlAnalysisResponse analyzeUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            throw new BadRequestException("URL must not be blank");
        }

        URI initialUri = validateAndParseUri(rawUrl);
        String originalUrl = initialUri.toString();
        List<String> suspiciousReasons = new ArrayList<>();
        List<String> redirectChain = new ArrayList<>();
        redirectChain.add(originalUrl);

        String host = initialUri.getHost();
        if (host == null) {
            throw new BadRequestException("URL does not contain a valid host: " + rawUrl);
        }
        host = host.toLowerCase(Locale.ROOT);

        // 1. SSRF pre-check on initial URI host
        boolean isSsrfBlocked = checkSsrfAndAddReason(host, suspiciousReasons);

        // 2. Detect lookalike domains targeting UPI and banking brands
        boolean isLookalike = checkLookalikeDomain(host, suspiciousReasons);

        // 3. Flag other suspicious patterns (IP host, excessive subdomains, shorteners, ports, high-risk TLDs)
        checkSuspiciousUrlPatterns(initialUri, host, suspiciousReasons);

        // 4. Trace redirects if safe from SSRF
        String finalUrl = originalUrl;
        if (!isSsrfBlocked) {
            finalUrl = traceRedirects(initialUri, redirectChain, suspiciousReasons);
        }

        boolean isSuspicious = isLookalike || !suspiciousReasons.isEmpty();

        return UrlAnalysisResponse.builder()
                .originalUrl(originalUrl)
                .finalUrl(finalUrl)
                .redirectChain(redirectChain)
                .isSuspicious(isSuspicious)
                .suspiciousReasons(suspiciousReasons)
                .domainAge("Unknown")
                .isLookalikeDomain(isLookalike)
                .build();
    }

    /**
     * Legacy convenience method delegating to analyzeUrl.
     *
     * @param url input URL
     * @return UrlAnalysisResponse
     */
    public UrlAnalysisResponse analyze(String url) {
        return analyzeUrl(url);
    }

    private URI validateAndParseUri(String rawUrl) {
        String trimmed = rawUrl.trim();
        if (!trimmed.toLowerCase(Locale.ROOT).startsWith("http://") && !trimmed.toLowerCase(Locale.ROOT).startsWith("https://")) {
            trimmed = "https://" + trimmed;
        }

        try {
            URI uri = new URI(trimmed);
            String scheme = uri.getScheme();
            if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
                throw new BadRequestException("Invalid URL scheme (only http/https supported): " + rawUrl);
            }
            if (uri.getHost() == null || uri.getHost().isBlank()) {
                throw new BadRequestException("Invalid URL host: " + rawUrl);
            }
            return uri;
        } catch (URISyntaxException e) {
            throw new BadRequestException("Invalid URL syntax: " + rawUrl, e);
        }
    }

    /**
     * SSRF Protection: Checks if the hostname or resolved IP is a private/internal address.
     * Blocks 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x, loopback, link-local, and internal names.
     */
    private boolean checkSsrfAndAddReason(String host, List<String> suspiciousReasons) {
        if (isLocalOrInternalHostname(host)) {
            suspiciousReasons.add("SSRF protection: Request to internal/local hostname blocked (" + host + ")");
            return true;
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress addr : addresses) {
                if (isPrivateOrInternalIp(addr)) {
                    suspiciousReasons.add("SSRF protection: Request to private/internal IP address blocked (" + addr.getHostAddress() + ")");
                    return true;
                }
            }
        } catch (UnknownHostException e) {
            log.debug("Unable to resolve host: {}", host);
            // Non-resolvable hosts are recorded but not immediately flagged as SSRF
        }
        return false;
    }

    private boolean isLocalOrInternalHostname(String host) {
        return host.equalsIgnoreCase("localhost")
                || host.endsWith(".localhost")
                || host.endsWith(".local")
                || host.endsWith(".internal")
                || host.endsWith(".lan");
    }

    /**
     * Blocks private/internal IPs: 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x, and IPv6 private spaces.
     */
    public boolean isPrivateOrInternalIp(InetAddress address) {
        if (address == null) {
            return false;
        }

        if (address.isLoopbackAddress() || address.isSiteLocalAddress()
                || address.isLinkLocalAddress() || address.isAnyLocalAddress()) {
            return true;
        }

        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            int b0 = bytes[0] & 0xFF;
            int b1 = bytes[1] & 0xFF;

            // 10.0.0.0/8
            if (b0 == 10) return true;
            // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
            if (b0 == 172 && (b1 >= 16 && b1 <= 31)) return true;
            // 192.168.0.0/16
            if (b0 == 192 && b1 == 168) return true;
            // 127.0.0.0/8
            if (b0 == 127) return true;
            // 169.254.0.0/16 (link-local, cloud metadata service)
            if (b0 == 169 && b1 == 254) return true;
            // 0.0.0.0/8
            if (b0 == 0) return true;
            // 100.64.0.0/10 (Carrier-Grade NAT)
            if (b0 == 100 && (b1 >= 64 && b1 <= 127)) return true;
        }
        return false;
    }

    /**
     * Lookalike domain detection for common bank and UPI brands.
     */
    private boolean checkLookalikeDomain(String host, List<String> suspiciousReasons) {
        String cleanHost = host.startsWith("www.") ? host.substring(4) : host;

        for (BrandTarget target : TARGET_BRANDS) {
            // Check if domain is an official domain of the brand
            boolean isOfficial = target.officialDomains().stream()
                    .anyMatch(d -> cleanHost.equals(d) || cleanHost.endsWith("." + d));

            if (isOfficial) {
                continue; // Legitimate official brand domain
            }

            String brand = target.brandName();

            // Check if host contains brand combined with hyphens or security keywords (e.g. paytm-secure, googlepay-verify)
            if (cleanHost.contains(brand + "-") || cleanHost.contains("-" + brand)
                    || cleanHost.contains(brand + "secure") || cleanHost.contains(brand + "verify")
                    || cleanHost.contains(brand + "kyc") || cleanHost.contains(brand + "pay")
                    || cleanHost.contains(brand + "online") || cleanHost.contains(brand + "support")) {
                suspiciousReasons.add("Lookalike domain detected: " + host + " (mimics legitimate brand '" + brand + "')");
                return true;
            }

            // Check Levenshtein edit distance on domain segments
            String[] segments = cleanHost.split("\\.");
            for (String segment : segments) {
                if (segment.length() >= 3 && Math.abs(segment.length() - brand.length()) <= 2) {
                    int dist = computeLevenshteinDistance(segment, brand);
                    if (dist > 0 && dist <= 2 && !segment.equals(brand)) {
                        suspiciousReasons.add("Lookalike domain misspelling detected: '" + segment + "' resembles brand '" + brand + "'");
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private void checkSuspiciousUrlPatterns(URI uri, String host, List<String> suspiciousReasons) {
        // 1. IP-based URL
        if (IPV4_PATTERN.matcher(host).matches() || host.startsWith("[") && host.endsWith("]")) {
            suspiciousReasons.add("IP-based URL detected: Uses raw IP address (" + host + ") instead of domain name");
        }

        // 2. URL Shorteners
        if (URL_SHORTENERS.contains(host)) {
            suspiciousReasons.add("URL shortener detected: " + host + " (obscures true destination)");
        }

        // 3. Excessive subdomains (>= 4 dots in domain)
        int dotCount = 0;
        for (int i = 0; i < host.length(); i++) {
            if (host.charAt(i) == '.') dotCount++;
        }
        if (dotCount >= 3) {
            suspiciousReasons.add("Excessive subdomain levels detected (" + (dotCount + 1) + " labels in host: " + host + ")");
        }

        // 4. Suspicious / high-risk TLD
        int lastDot = host.lastIndexOf('.');
        if (lastDot > 0 && lastDot < host.length() - 1) {
            String tld = host.substring(lastDot + 1);
            if (SUSPICIOUS_TLDS.contains(tld)) {
                suspiciousReasons.add("Suspicious top-level domain detected: ." + tld);
            }
        }

        // 5. Scam keywords in domain
        for (String keyword : SCAM_KEYWORDS) {
            if (host.contains(keyword)) {
                suspiciousReasons.add("Domain contains high-risk scam keyword: '" + keyword + "'");
                break;
            }
        }

        // 6. Non-standard ports
        int port = uri.getPort();
        if (port != -1 && port != 80 && port != 443) {
            suspiciousReasons.add("Non-standard port detected: " + port);
        }
    }

    /**
     * Safely traces HTTP redirect chains up to maxRedirects, performing SSRF validation
     * on every redirect hop.
     */
    private String traceRedirects(URI currentUri, List<String> redirectChain, List<String> suspiciousReasons) {
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(redirectTimeoutMs))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        URI uri = currentUri;
        int hops = 0;

        while (hops < maxRedirects) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(uri)
                        .timeout(Duration.ofMillis(redirectTimeoutMs))
                        .header("User-Agent", "UPI-Shield-UrlAnalyzer/1.0")
                        .method("HEAD", HttpRequest.BodyPublishers.noBody())
                        .build();

                HttpResponse<Void> response;
                try {
                    response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
                } catch (IOException e) {
                    // If HEAD is rejected with 405 Method Not Allowed, fallback to GET
                    HttpRequest getRequest = HttpRequest.newBuilder()
                            .uri(uri)
                            .timeout(Duration.ofMillis(redirectTimeoutMs))
                            .header("User-Agent", "UPI-Shield-UrlAnalyzer/1.0")
                            .GET()
                            .build();
                    response = httpClient.send(getRequest, HttpResponse.BodyHandlers.discarding());
                }

                int statusCode = response.statusCode();
                if (isRedirectStatusCode(statusCode)) {
                    String location = response.headers().firstValue("Location").orElse(null);
                    if (location == null || location.isBlank()) {
                        break;
                    }

                    URI nextUri = uri.resolve(location);
                    String nextUrl = nextUri.toString();

                    // Check SSRF on target of redirect
                    String nextHost = nextUri.getHost();
                    if (nextHost != null && checkSsrfAndAddReason(nextHost, suspiciousReasons)) {
                        redirectChain.add(nextUrl + " [BLOCKED_SSRF]");
                        return nextUrl;
                    }

                    redirectChain.add(nextUrl);
                    uri = nextUri;
                    hops++;
                } else {
                    break;
                }
            } catch (Exception e) {
                log.debug("Redirect trace stopped at {} due to: {}", uri, e.getMessage());
                break;
            }
        }

        return uri.toString();
    }

    private boolean isRedirectStatusCode(int statusCode) {
        return statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308;
    }

    private int computeLevenshteinDistance(String s1, String s2) {
        int len1 = s1.length();
        int len2 = s2.length();
        int[][] dp = new int[len1 + 1][len2 + 1];

        for (int i = 0; i <= len1; i++) dp[i][0] = i;
        for (int j = 0; j <= len2; j++) dp[0][j] = j;

        for (int i = 1; i <= len1; i++) {
            for (int j = 1; j <= len2; j++) {
                int cost = (s1.charAt(i - 1) == s2.charAt(j - 1)) ? 0 : 1;
                dp[i][j] = Math.min(
                        Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                        dp[i - 1][j - 1] + cost
                );
            }
        }
        return dp[len1][len2];
    }

    private record BrandTarget(String brandName, Set<String> officialDomains) {}
}
