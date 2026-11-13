package com.sme.cyberrisk;

import com.sme.cyberrisk.model.*;
import com.sme.cyberrisk.service.RiskScoringService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RiskScoringServiceTest {

    private RiskScoringService scoringService;

    @BeforeEach
    void setUp() {
        scoringService = new RiskScoringService();
    }

    @Test
    @DisplayName("Should return 0 risk and A+ grade when there are no findings")
    void testZeroFindingsRisk() {
        RiskScoringService.RiskEvaluation eval = scoringService.calculateAssetRisk(List.of(), Criticality.MEDIUM);
        assertEquals(0, eval.riskScore());
        assertEquals(100, eval.healthScore());
        assertEquals("Low", eval.riskLevel());
        assertEquals("A+", eval.grade());
    }

    @Test
    @DisplayName("Should automatically flag Critical Risk (>= 70) if any CRITICAL finding exists")
    void testCriticalFindingAutomaticThreshold() {
        List<Finding> findings = new ArrayList<>();
        findings.add(new Finding(
            FindingCategory.NETWORK_PORTS,
            Severity.CRITICAL,
            "Exposed RDP Port 3389",
            "RDP exposed to public internet",
            "Block port 3389",
            "10 mins"
        ));

        RiskScoringService.RiskEvaluation eval = scoringService.calculateAssetRisk(findings, Criticality.CRITICAL);
        assertTrue(eval.riskScore() >= 70, "Risk score must be at least 70 for critical finding on critical asset");
        assertEquals("Critical", eval.riskLevel());
    }

    @Test
    @DisplayName("Criticality multiplier should escalate risk on critical assets compared to low assets")
    void testCriticalityMultiplierEffect() {
        List<Finding> findings = List.of(
            new Finding(FindingCategory.HTTP_HEADERS, Severity.MEDIUM, "Missing HSTS", "Desc", "Rem", "10m"),
            new Finding(FindingCategory.EMAIL_SECURITY, Severity.HIGH, "Missing SPF", "Desc", "Rem", "15m")
        );

        RiskScoringService.RiskEvaluation evalLow = scoringService.calculateAssetRisk(findings, Criticality.LOW);
        RiskScoringService.RiskEvaluation evalCrit = scoringService.calculateAssetRisk(findings, Criticality.CRITICAL);

        assertTrue(evalCrit.riskScore() > evalLow.riskScore(),
            "Critical asset should have higher risk score than Low asset with identical findings");
    }

    @Test
    @DisplayName("Should assign proper grades based on health score")
    void testGradeAssignment() {
        assertEquals("A+", scoringService.determineGrade(95));
        assertEquals("A", scoringService.determineGrade(85));
        assertEquals("B", scoringService.determineGrade(75));
        assertEquals("C", scoringService.determineGrade(65));
        assertEquals("D", scoringService.determineGrade(50));
        assertEquals("F", scoringService.determineGrade(30));
    }
}
