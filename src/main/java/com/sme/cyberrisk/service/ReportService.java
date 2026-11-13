package com.sme.cyberrisk.service;

import com.sme.cyberrisk.model.*;
import com.sme.cyberrisk.repository.AssetRepository;
import com.sme.cyberrisk.repository.FindingRepository;
import com.sme.cyberrisk.repository.ScanResultRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class ReportService {

    private final AssetRepository assetRepo;
    private final ScanResultRepository scanRepo;
    private final FindingRepository findingRepo;
    private final ComplianceService complianceService;
    private final RiskScoringService riskScoringService;

    public ReportService(
        AssetRepository assetRepo,
        ScanResultRepository scanRepo,
        FindingRepository findingRepo,
        ComplianceService complianceService,
        RiskScoringService riskScoringService
    ) {
        this.assetRepo = assetRepo;
        this.scanRepo = scanRepo;
        this.findingRepo = findingRepo;
        this.complianceService = complianceService;
        this.riskScoringService = riskScoringService;
    }

    public record ExecutiveDashboardStats(
        int companyHealthScore,
        int companyRiskScore,
        String companyGrade,
        String overallRiskLevel,
        long totalAssets,
        long criticalAssets,
        long highRiskAssets,
        long totalFindings,
        long criticalFindings,
        long highFindings,
        long mediumFindings,
        long lowFindings,
        int complianceScore,
        List<Finding> topRisks,
        List<Finding> quickWins,
        List<ScanResult> recentScans
    ) {}

    public ExecutiveDashboardStats getDashboardStats() {
        List<Asset> assets = assetRepo.findAll();
        long totalAssets = assets.size();

        int avgRisk = 0;
        if (!assets.isEmpty()) {
            double sum = assets.stream().mapToInt(Asset::getCurrentRiskScore).sum();
            avgRisk = (int) Math.round(sum / assets.size());
        }

        ComplianceService.ComplianceSummary comp = complianceService.getSummary();
        // Blend in governance score (15% weight)
        int governancePenalty = (100 - comp.overallScorePercentage()) / 4;
        int compositeRisk = Math.min(100, Math.max(0, (int) Math.round((avgRisk * 0.85) + (governancePenalty * 0.15))));
        int companyHealth = Math.max(0, 100 - compositeRisk);

        String riskLevel = riskScoringService.determineLevel(compositeRisk);
        String grade = riskScoringService.determineGrade(companyHealth);

        long criticalAssets = assets.stream().filter(a -> "Critical".equalsIgnoreCase(a.getCurrentRiskLevel())).count();
        long highAssets = assets.stream().filter(a -> "High".equalsIgnoreCase(a.getCurrentRiskLevel())).count();

        List<Finding> allFindings = findingRepo.findAll();
        long critFindings = allFindings.stream().filter(f -> f.getSeverity() == Severity.CRITICAL).count();
        long highFindings = allFindings.stream().filter(f -> f.getSeverity() == Severity.HIGH).count();
        long medFindings = allFindings.stream().filter(f -> f.getSeverity() == Severity.MEDIUM).count();
        long lowFindings = allFindings.stream().filter(f -> f.getSeverity() == Severity.LOW).count();

        List<Finding> topRisks = allFindings.stream()
            .filter(f -> f.getSeverity() == Severity.CRITICAL || f.getSeverity() == Severity.HIGH)
            .distinct()
            .limit(6)
            .collect(Collectors.toList());

        List<Finding> quickWins = allFindings.stream()
            .filter(f -> f.getRemediationTimeEstimate() != null &&
                        (f.getRemediationTimeEstimate().contains("5 min") || f.getRemediationTimeEstimate().contains("10 min")))
            .distinct()
            .limit(5)
            .collect(Collectors.toList());

        List<ScanResult> recentScans = scanRepo.findTop10ByOrderByScanDateDesc();

        return new ExecutiveDashboardStats(
            companyHealth,
            compositeRisk,
            grade,
            riskLevel,
            totalAssets,
            criticalAssets,
            highAssets,
            allFindings.size(),
            critFindings,
            highFindings,
            medFindings,
            lowFindings,
            comp.overallScorePercentage(),
            topRisks,
            quickWins,
            recentScans
        );
    }
}
