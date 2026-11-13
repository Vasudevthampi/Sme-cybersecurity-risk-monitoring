package com.sme.cyberrisk.model;

public enum FindingCategory {
    NETWORK_PORTS("Network & Open Ports"),
    SSL_TLS("SSL/TLS & Cryptography"),
    HTTP_HEADERS("HTTP Security Headers"),
    EMAIL_SECURITY("Email & Phishing Defense (SPF/DMARC)"),
    VULNERABILITY_CVE("Known Vulnerabilities (CVE)"),
    GOVERNANCE("NIST CSF Governance");

    private final String title;

    FindingCategory(String title) {
        this.title = title;
    }

    public String getTitle() {
        return title;
    }
}
