package com.sme.cyberrisk.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "scan_results")
public class ScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "asset_id", nullable = false)
    private Asset asset;

    private LocalDateTime scanDate = LocalDateTime.now();

    private long scanDurationMs;

    private int portsScanned;

    private String openPorts; // e.g. "80, 443"

    private Boolean sslValid;

    private Integer sslDaysRemaining;

    private String sslIssuer;

    private String sslProtocol;

    @Column(length = 1000)
    private String missingHeaders;

    @Column(length = 1000)
    private String spfRecord;

    @Column(length = 1000)
    private String dmarcRecord;

    private Boolean emailSpoofable;

    private int riskScore; // 0 - 100

    private String riskLevel; // Low, Medium, High, Critical

    @Column(length = 2000)
    private String summary;

    @OneToMany(mappedBy = "scanResult", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Finding> findings = new ArrayList<>();

    public ScanResult() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Asset getAsset() { return asset; }
    public void setAsset(Asset asset) { this.asset = asset; }

    public LocalDateTime getScanDate() { return scanDate; }
    public void setScanDate(LocalDateTime scanDate) { this.scanDate = scanDate; }

    public long getScanDurationMs() { return scanDurationMs; }
    public void setScanDurationMs(long scanDurationMs) { this.scanDurationMs = scanDurationMs; }

    public int getPortsScanned() { return portsScanned; }
    public void setPortsScanned(int portsScanned) { this.portsScanned = portsScanned; }

    public String getOpenPorts() { return openPorts; }
    public void setOpenPorts(String openPorts) { this.openPorts = openPorts; }

    public Boolean getSslValid() { return sslValid; }
    public void setSslValid(Boolean sslValid) { this.sslValid = sslValid; }

    public Integer getSslDaysRemaining() { return sslDaysRemaining; }
    public void setSslDaysRemaining(Integer sslDaysRemaining) { this.sslDaysRemaining = sslDaysRemaining; }

    public String getSslIssuer() { return sslIssuer; }
    public void setSslIssuer(String sslIssuer) { this.sslIssuer = sslIssuer; }

    public String getSslProtocol() { return sslProtocol; }
    public void setSslProtocol(String sslProtocol) { this.sslProtocol = sslProtocol; }

    public String getMissingHeaders() { return missingHeaders; }
    public void setMissingHeaders(String missingHeaders) { this.missingHeaders = missingHeaders; }

    public String getSpfRecord() { return spfRecord; }
    public void setSpfRecord(String spfRecord) { this.spfRecord = spfRecord; }

    public String getDmarcRecord() { return dmarcRecord; }
    public void setDmarcRecord(String dmarcRecord) { this.dmarcRecord = dmarcRecord; }

    public Boolean getEmailSpoofable() { return emailSpoofable; }
    public void setEmailSpoofable(Boolean emailSpoofable) { this.emailSpoofable = emailSpoofable; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }

    public List<Finding> getFindings() { return findings; }
    public void setFindings(List<Finding> findings) { this.findings = findings; }

    public void addFinding(Finding finding) {
        findings.add(finding);
        finding.setScanResult(this);
    }
}
