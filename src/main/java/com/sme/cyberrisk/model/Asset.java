package com.sme.cyberrisk.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "assets")
public class Asset {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Asset name is required")
    @Column(nullable = false)
    private String name;

    @NotBlank(message = "Target address (domain, URL, or IP) is required")
    @Column(nullable = false)
    private String target;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AssetType type;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Criticality criticality;

    private String department;

    @Column(length = 1000)
    private String description;

    private boolean active = true;

    private LocalDateTime lastScanDate;

    private int currentRiskScore = 0; // 0 (safest) to 100 (highest risk)

    private String currentRiskLevel = "Low";

    private LocalDateTime createdAt = LocalDateTime.now();

    @OneToMany(mappedBy = "asset", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("scanDate DESC")
    private List<ScanResult> scanResults = new ArrayList<>();

    public Asset() {}

    public Asset(String name, String target, AssetType type, Criticality criticality, String department, String description) {
        this.name = name;
        this.target = target;
        this.type = type;
        this.criticality = criticality;
        this.department = department;
        this.description = description;
        this.createdAt = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getTarget() { return target; }
    public void setTarget(String target) { this.target = target; }

    public AssetType getType() { return type; }
    public void setType(AssetType type) { this.type = type; }

    public Criticality getCriticality() { return criticality; }
    public void setCriticality(Criticality criticality) { this.criticality = criticality; }

    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }

    public LocalDateTime getLastScanDate() { return lastScanDate; }
    public void setLastScanDate(LocalDateTime lastScanDate) { this.lastScanDate = lastScanDate; }

    public int getCurrentRiskScore() { return currentRiskScore; }
    public void setCurrentRiskScore(int currentRiskScore) { this.currentRiskScore = currentRiskScore; }

    public String getCurrentRiskLevel() { return currentRiskLevel; }
    public void setCurrentRiskLevel(String currentRiskLevel) { this.currentRiskLevel = currentRiskLevel; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public List<ScanResult> getScanResults() { return scanResults; }
    public void setScanResults(List<ScanResult> scanResults) { this.scanResults = scanResults; }

    public int getHealthScore() {
        return Math.max(0, 100 - currentRiskScore);
    }

    public String getCleanTargetHost() {
        if (target == null) return "";
        String clean = target.trim();
        if (clean.startsWith("http://")) clean = clean.substring(7);
        if (clean.startsWith("https://")) clean = clean.substring(8);
        int slashIdx = clean.indexOf('/');
        if (slashIdx != -1) clean = clean.substring(0, slashIdx);
        int colonIdx = clean.indexOf(':');
        if (colonIdx != -1) clean = clean.substring(0, colonIdx);
        return clean;
    }
}
