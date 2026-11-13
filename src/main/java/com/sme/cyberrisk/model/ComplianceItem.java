package com.sme.cyberrisk.model;

import jakarta.persistence.*;

@Entity
@Table(name = "compliance_items")
public class ComplianceItem {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String nistCategory; // IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER

    @Column(nullable = false)
    private String code; // e.g. "PR.AC-1"

    @Column(nullable = false)
    private String title;

    @Column(length = 2000, nullable = false)
    private String description;

    @Column(nullable = false)
    private String status = "NOT_IMPLEMENTED"; // IMPLEMENTED, PARTIAL, NOT_IMPLEMENTED

    private int weight = 3; // 1 to 5

    @Column(length = 2000)
    private String guidance;

    public ComplianceItem() {}

    public ComplianceItem(String nistCategory, String code, String title, String description, String status, int weight, String guidance) {
        this.nistCategory = nistCategory;
        this.code = code;
        this.title = title;
        this.description = description;
        this.status = status;
        this.weight = weight;
        this.guidance = guidance;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getNistCategory() { return nistCategory; }
    public void setNistCategory(String nistCategory) { this.nistCategory = nistCategory; }

    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public int getWeight() { return weight; }
    public void setWeight(int weight) { this.weight = weight; }

    public String getGuidance() { return guidance; }
    public void setGuidance(String guidance) { this.guidance = guidance; }

    public int getComplianceScorePercentage() {
        if ("IMPLEMENTED".equalsIgnoreCase(status)) return 100;
        if ("PARTIAL".equalsIgnoreCase(status)) return 50;
        return 0;
    }
}
