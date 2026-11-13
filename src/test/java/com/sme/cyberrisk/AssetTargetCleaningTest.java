package com.sme.cyberrisk;

import com.sme.cyberrisk.model.Asset;
import com.sme.cyberrisk.model.AssetType;
import com.sme.cyberrisk.model.Criticality;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AssetTargetCleaningTest {

    @Test
    @DisplayName("Should strip protocol, paths, and ports to extract clean host")
    void testCleanTargetHost() {
        Asset a1 = new Asset("Web", "https://portal.company.com/login", AssetType.WEB_APP, Criticality.HIGH, "IT", "");
        assertEquals("portal.company.com", a1.getCleanTargetHost());

        Asset a2 = new Asset("API", "http://api.company.com:8443/v1/test", AssetType.WEB_APP, Criticality.MEDIUM, "IT", "");
        assertEquals("api.company.com", a2.getCleanTargetHost());

        Asset a3 = new Asset("IP", "192.168.1.1", AssetType.INTERNAL_HOST, Criticality.LOW, "IT", "");
        assertEquals("192.168.1.1", a3.getCleanTargetHost());
    }

    @Test
    @DisplayName("Health score should be 100 minus risk score")
    void testHealthScoreCalculation() {
        Asset a = new Asset("Test", "test.com", AssetType.DOMAIN, Criticality.MEDIUM, "IT", "");
        a.setCurrentRiskScore(35);
        assertEquals(65, a.getHealthScore());

        a.setCurrentRiskScore(95);
        assertEquals(5, a.getHealthScore());
    }
}
