package com.sme.cyberrisk.model;

import jakarta.persistence.*;

@Entity
@Table(name = "findings")
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_result_id")
    private ScanResult scanResult;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FindingCategory category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    @Column(nullable = false)
    private String title;

    @Column(length = 2000)
    private String description;

    @Column(length = 3000)
    private String remediation;

    private String remediationTimeEstimate;

    private String cveId;

    public Finding() {}

    public Finding(FindingCategory category, Severity severity, String title, String description, String remediation, String remediationTimeEstimate) {
        this.category = category;
        this.severity = severity;
        this.title = title;
        this.description = description;
        this.remediation = remediation;
        this.remediationTimeEstimate = remediationTimeEstimate;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public ScanResult getScanResult() { return scanResult; }
    public void setScanResult(ScanResult scanResult) { this.scanResult = scanResult; }

    public FindingCategory getCategory() { return category; }
    public void setCategory(FindingCategory category) { this.category = category; }

    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getRemediation() { return remediation; }
    public void setRemediation(String remediation) { this.remediation = remediation; }

    public String getRemediationTimeEstimate() { return remediationTimeEstimate; }
    public void setRemediationTimeEstimate(String remediationTimeEstimate) { this.remediationTimeEstimate = remediationTimeEstimate; }

    public String getCveId() { return cveId; }
    public void setCveId(String cveId) { this.cveId = cveId; }
}
