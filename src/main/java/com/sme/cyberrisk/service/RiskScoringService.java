package com.sme.cyberrisk.service;

import com.sme.cyberrisk.model.Criticality;
import com.sme.cyberrisk.model.Finding;
import com.sme.cyberrisk.model.FindingCategory;
import com.sme.cyberrisk.model.Severity;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class RiskScoringService {

    public record RiskEvaluation(int riskScore, int healthScore, String riskLevel, String grade, Map<FindingCategory, Integer> categoryScores) {}

    public RiskEvaluation calculateAssetRisk(List<Finding> findings, Criticality criticality) {
        if (findings == null || findings.isEmpty()) {
            return new RiskEvaluation(0, 100, "Low", "A+", Map.of());
        }

        // Group findings by category and calculate raw penalty sum
        Map<FindingCategory, List<Finding>> grouped = findings.stream()
            .collect(Collectors.groupingBy(Finding::getCategory));

        int portScore = calculateCategoryPenalty(grouped.get(FindingCategory.NETWORK_PORTS), 35);
        int sslScore = calculateCategoryPenalty(grouped.get(FindingCategory.SSL_TLS), 30);
        int headerScore = calculateCategoryPenalty(grouped.get(FindingCategory.HTTP_HEADERS), 25);
        int emailScore = calculateCategoryPenalty(grouped.get(FindingCategory.EMAIL_SECURITY), 30);
        int cveScore = calculateCategoryPenalty(grouped.get(FindingCategory.VULNERABILITY_CVE), 35);

        // Weighted aggregation:
        // Ports: 25%, SSL: 20%, Headers: 15%, Email: 20%, CVE: 20%
        double compositeRaw = (portScore * 0.25) +
                              (sslScore * 0.20) +
                              (headerScore * 0.15) +
                              (emailScore * 0.20) +
                              (cveScore * 0.20);

        // Apply criticality multiplier
        double multiplier = criticality != null ? criticality.getMultiplier() : 1.0;
        int finalRiskScore = (int) Math.min(100, Math.round(compositeRaw * multiplier));

        // Automatic bump if any CRITICAL severity finding is present
        boolean hasCriticalFinding = findings.stream().anyMatch(f -> f.getSeverity() == Severity.CRITICAL);
        if (hasCriticalFinding && finalRiskScore < 70) {
            finalRiskScore = Math.max(finalRiskScore, 70);
        }

        int healthScore = Math.max(0, 100 - finalRiskScore);
        String level = determineLevel(finalRiskScore);
        String grade = determineGrade(healthScore);

        Map<FindingCategory, Integer> categoryScores = Map.of(
            FindingCategory.NETWORK_PORTS, portScore,
            FindingCategory.SSL_TLS, sslScore,
            FindingCategory.HTTP_HEADERS, headerScore,
            FindingCategory.EMAIL_SECURITY, emailScore,
            FindingCategory.VULNERABILITY_CVE, cveScore
        );

        return new RiskEvaluation(finalRiskScore, healthScore, level, grade, categoryScores);
    }

    private int calculateCategoryPenalty(List<Finding> categoryFindings, int maxCategoryScore) {
        if (categoryFindings == null || categoryFindings.isEmpty()) return 0;
        int totalPenalty = 0;
        for (Finding f : categoryFindings) {
            totalPenalty += f.getSeverity().getPenaltyScore();
        }
        return Math.min(100, (int) Math.round(((double) totalPenalty / maxCategoryScore) * 100));
    }

    public String determineLevel(int riskScore) {
        if (riskScore >= 70) return "Critical";
        if (riskScore >= 50) return "High";
        if (riskScore >= 25) return "Medium";
        return "Low";
    }

    public String determineGrade(int healthScore) {
        if (healthScore >= 90) return "A+";
        if (healthScore >= 80) return "A";
        if (healthScore >= 70) return "B";
        if (healthScore >= 60) return "C";
        if (healthScore >= 45) return "D";
        return "F";
    }
}
