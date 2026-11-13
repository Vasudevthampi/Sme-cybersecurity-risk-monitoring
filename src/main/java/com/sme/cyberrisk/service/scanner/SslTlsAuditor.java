package com.sme.cyberrisk.service.scanner;

import com.sme.cyberrisk.model.Finding;
import com.sme.cyberrisk.model.FindingCategory;
import com.sme.cyberrisk.model.Severity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Component
public class SslTlsAuditor {

    @Value("${sme.scanner.socket-timeout-ms:2000}")
    private int timeoutMs;

    public record SslReport(boolean valid, Integer daysRemaining, String issuer, String protocol, List<Finding> findings) {}

    public SslReport inspect(String host, int port) {
        List<Finding> findings = new ArrayList<>();
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new SecureRandom());

            SSLSocketFactory factory = sc.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
                socket.connect(new java.net.InetSocketAddress(host, port), timeoutMs);
                socket.setSoTimeout(timeoutMs);
                socket.startHandshake();

                SSLSession session = socket.getSession();
                String protocol = session.getProtocol();
                Certificate[] certs = session.getPeerCertificates();

                if (certs.length == 0 || !(certs[0] instanceof X509Certificate x509)) {
                    findings.add(new Finding(
                        FindingCategory.SSL_TLS,
                        Severity.HIGH,
                        "Missing or Invalid SSL/TLS Certificate",
                        "The target host did not present a valid X.509 certificate chain.",
                        "Install a trusted SSL/TLS certificate from a recognized Certificate Authority (e.g., Let's Encrypt).",
                        "30 mins"
                    ));
                    return new SslReport(false, null, "Unknown", protocol, findings);
                }

                String issuer = x509.getIssuerX500Principal().getName();
                Date notAfter = x509.getNotAfter();
                Date notBefore = x509.getNotBefore();
                Instant now = Instant.now();

                int daysRemaining = (int) ChronoUnit.DAYS.between(now, notAfter.toInstant());

                // Expiration checks
                if (now.isAfter(notAfter.toInstant())) {
                    findings.add(new Finding(
                        FindingCategory.SSL_TLS,
                        Severity.CRITICAL,
                        "SSL/TLS Certificate Expired",
                        "The SSL certificate expired " + Math.abs(daysRemaining) + " day(s) ago on " + notAfter + ". Browsers will actively block user traffic with security warnings.",
                        "Immediately renew and install a current SSL certificate. Consider configuring automated renewal with certbot.",
                        "15 mins"
                    ));
                    return new SslReport(false, daysRemaining, issuer, protocol, findings);
                } else if (daysRemaining <= 14) {
                    findings.add(new Finding(
                        FindingCategory.SSL_TLS,
                        Severity.HIGH,
                        "SSL Certificate Expiring Soon (" + daysRemaining + " days)",
                        "The SSL certificate will expire in " + daysRemaining + " day(s). If left unaddressed, customer access will be severed.",
                        "Renew the certificate promptly before expiry.",
                        "20 mins"
                    ));
                } else if (daysRemaining <= 30) {
                    findings.add(new Finding(
                        FindingCategory.SSL_TLS,
                        Severity.MEDIUM,
                        "SSL Certificate Renewal Window Open (" + daysRemaining + " days)",
                        "The certificate has " + daysRemaining + " days remaining before expiration.",
                        "Verify that automated renewal (e.g. Let's Encrypt / ACME) is scheduled.",
                        "10 mins"
                    ));
                }

                // Protocol check (TLS 1.0 / 1.1 / SSLv3 deprecation)
                if ("TLSv1".equals(protocol) || "TLSv1.1".equals(protocol) || protocol.startsWith("SSL")) {
                    findings.add(new Finding(
                        FindingCategory.SSL_TLS,
                        Severity.HIGH,
                        "Deprecated Protocol In Use (" + protocol + ")",
                        "The server negotiates connections using legacy protocol " + protocol + ", which suffers from known cryptographic flaws (POODLE, BEAST).",
                        "Update web server configuration to disable SSLv3, TLS 1.0, and TLS 1.1. Allow only TLS 1.2 and TLS 1.3.",
                        "20 mins"
                    ));
                }

                return new SslReport(true, daysRemaining, issuer, protocol, findings);
            }
        } catch (Exception e) {
            // Port 443 might be closed or not SSL
            findings.add(new Finding(
                FindingCategory.SSL_TLS,
                Severity.HIGH,
                "Unable to Establish Secure SSL/TLS Session",
                "Connection failed on port " + port + ": " + (e.getMessage() != null ? e.getMessage() : "Connection refused/timeout"),
                "Ensure HTTPS service is configured and accessible.",
                "30 mins"
            ));
            return new SslReport(false, 0, "None", "None", findings);
        }
    }
}
