package com.sme.cyberrisk.service.scanner;

import com.sme.cyberrisk.model.Finding;
import com.sme.cyberrisk.model.FindingCategory;
import com.sme.cyberrisk.model.Severity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;

@Component
public class HttpHeaderAuditor {

    @Value("${sme.scanner.http-timeout-ms:3500}")
    private int timeoutMs;

    public record HeaderReport(List<String> missingHeaders, String serverBanner, List<Finding> findings) {}

    public HeaderReport auditHeaders(String host) {
        List<String> missingHeaders = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();
        String serverBanner = "None Detected";

        String url = host.startsWith("http://") || host.startsWith("https://") ? host : "https://" + host;

        try {
            HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofMillis(timeoutMs))
                .build();

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofMillis(timeoutMs))
                .header("User-Agent", "SME-CyberRisk-Monitor/1.0")
                .GET()
                .build();

            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            Map<String, List<String>> headers = response.headers().map();

            // 1. Strict-Transport-Security (HSTS)
            if (!hasHeader(headers, "strict-transport-security")) {
                missingHeaders.add("Strict-Transport-Security");
                findings.add(new Finding(
                    FindingCategory.HTTP_HEADERS,
                    Severity.MEDIUM,
                    "Missing Strict-Transport-Security (HSTS) Header",
                    "Without HSTS, attackers on the local network (e.g. coffee shop WiFi) can perform SSL stripping attacks to intercept user traffic in plaintext.",
                    "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    "10 mins"
                ));
            }

            // 2. Content-Security-Policy (CSP)
            if (!hasHeader(headers, "content-security-policy")) {
                missingHeaders.add("Content-Security-Policy");
                findings.add(new Finding(
                    FindingCategory.HTTP_HEADERS,
                    Severity.MEDIUM,
                    "Missing Content-Security-Policy (CSP) Header",
                    "No Content-Security-Policy header was detected. CSP restricts malicious script injection and mitigates Cross-Site Scripting (XSS) attacks.",
                    "Define a Content-Security-Policy directive restricting script-src and object-src to trusted origins.",
                    "30 mins"
                ));
            }

            // 3. X-Frame-Options (Clickjacking)
            if (!hasHeader(headers, "x-frame-options") && !cspHasFrameAncestors(headers)) {
                missingHeaders.add("X-Frame-Options");
                findings.add(new Finding(
                    FindingCategory.HTTP_HEADERS,
                    Severity.MEDIUM,
                    "Missing X-Frame-Options (Clickjacking Risk)",
                    "Your website can be embedded in an invisible <iframe> on an attacker's malicious webpage to hijack customer clicks or steal logins (Clickjacking).",
                    "Add HTTP header: X-Frame-Options: SAMEORIGIN (or DENY).",
                    "5 mins"
                ));
            }

            // 4. X-Content-Type-Options
            if (!hasHeader(headers, "x-content-type-options")) {
                missingHeaders.add("X-Content-Type-Options");
                findings.add(new Finding(
                    FindingCategory.HTTP_HEADERS,
                    Severity.LOW,
                    "Missing X-Content-Type-Options Header",
                    "Prevents browsers from MIME-sniffing a response away from the declared content-type, which can lead to unexpected script execution.",
                    "Add HTTP header: X-Content-Type-Options: nosniff",
                    "5 mins"
                ));
            }

            // 5. Referrer-Policy
            if (!hasHeader(headers, "referrer-policy")) {
                missingHeaders.add("Referrer-Policy");
                findings.add(new Finding(
                    FindingCategory.HTTP_HEADERS,
                    Severity.LOW,
                    "Missing Referrer-Policy Header",
                    "Without this policy, full URLs containing sensitive tokens or query parameters may be leaked to external third-party links.",
                    "Add HTTP header: Referrer-Policy: strict-origin-when-cross-origin",
                    "5 mins"
                ));
            }

            // 6. Server Banner Information Disclosure
            List<String> serverVals = getHeaderValues(headers, "server");
            if (!serverVals.isEmpty()) {
                serverBanner = String.join(", ", serverVals);
                if (serverBanner.matches(".*[0-9]+\\.[0-9]+.*")) {
                    findings.add(new Finding(
                        FindingCategory.HTTP_HEADERS,
                        Severity.LOW,
                        "Server Version Disclosure Detected (" + serverBanner + ")",
                        "The web server advertises its exact software and version in HTTP headers. This aids attackers in pinpointing targeted CVE exploits.",
                        "Configure web server to suppress detailed version banners (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx).",
                        "10 mins"
                    ));
                }
            }

            List<String> poweredByVals = getHeaderValues(headers, "x-powered-by");
            if (!poweredByVals.isEmpty()) {
                findings.add(new Finding(
                    FindingCategory.HTTP_HEADERS,
                    Severity.LOW,
                    "X-Powered-By Banner Leaking Framework (" + String.join(", ", poweredByVals) + ")",
                    "Headers disclose backend framework technology (e.g., PHP, ASP.NET, Express).",
                    "Disable the X-Powered-By response header in your application or web server configuration.",
                    "5 mins"
                ));
            }

        } catch (Exception e) {
            findings.add(new Finding(
                FindingCategory.HTTP_HEADERS,
                Severity.INFO,
                "HTTP Headers Audit Notice",
                "Direct HTTP/HTTPS probe reached limit or host not responsive on web port: " + e.getMessage(),
                "Verify web server is up and accepting HTTP/HTTPS traffic.",
                "15 mins"
            ));
        }

        return new HeaderReport(missingHeaders, serverBanner, findings);
    }

    private boolean hasHeader(Map<String, List<String>> headers, String name) {
        for (String key : headers.keySet()) {
            if (key != null && key.equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }

    private List<String> getHeaderValues(Map<String, List<String>> headers, String name) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return Collections.emptyList();
    }

    private boolean cspHasFrameAncestors(Map<String, List<String>> headers) {
        List<String> csp = getHeaderValues(headers, "content-security-policy");
        for (String val : csp) {
            if (val != null && val.toLowerCase().contains("frame-ancestors")) {
                return true;
            }
        }
        return false;
    }
}
