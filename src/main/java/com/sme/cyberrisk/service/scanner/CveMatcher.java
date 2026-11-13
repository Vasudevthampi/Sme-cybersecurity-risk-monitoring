package com.sme.cyberrisk.service.scanner;

import com.sme.cyberrisk.model.Finding;
import com.sme.cyberrisk.model.FindingCategory;
import com.sme.cyberrisk.model.Severity;
import com.sme.cyberrisk.model.VulnerabilityInfo;
import com.sme.cyberrisk.repository.VulnerabilityInfoRepository;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class CveMatcher {

    private final VulnerabilityInfoRepository vulnRepo;

    public CveMatcher(VulnerabilityInfoRepository vulnRepo) {
        this.vulnRepo = vulnRepo;
    }

    public List<Finding> matchBanners(String serverBanner, List<Integer> openPorts) {
        List<Finding> findings = new ArrayList<>();
        if (serverBanner == null && openPorts == null) return findings;

        String lowerBanner = serverBanner != null ? serverBanner.toLowerCase() : "";

        // Query database CVE catalog
        List<VulnerabilityInfo> allVulns = vulnRepo.findAll();

        for (VulnerabilityInfo v : allVulns) {
            boolean matched = false;

            if (lowerBanner.contains(v.getComponent().toLowerCase())) {
                if (v.getAffectedVersionRegex() == null || v.getAffectedVersionRegex().isBlank()) {
                    matched = true;
                } else if (lowerBanner.matches(".*" + v.getAffectedVersionRegex() + ".*")) {
                    matched = true;
                }
            }

            // Port-based vulnerability flags
            if (openPorts != null) {
                if (v.getComponent().equalsIgnoreCase("RDP") && openPorts.contains(3389)) {
                    matched = true;
                }
                if (v.getComponent().equalsIgnoreCase("SMB") && openPorts.contains(445)) {
                    matched = true;
                }
                if (v.getComponent().equalsIgnoreCase("Telnet") && openPorts.contains(23)) {
                    matched = true;
                }
            }

            if (matched) {
                Finding f = new Finding(
                    FindingCategory.VULNERABILITY_CVE,
                    v.getSeverity(),
                    "[" + v.getCveId() + "] " + v.getTitle(),
                    "CVSS: " + v.getCvssScore() + " (" + v.getSeverity().getLabel() + ") - " + v.getDescription(),
                    v.getRemediation(),
                    "20 mins"
                );
                f.setCveId(v.getCveId());
                findings.add(f);
            }
        }

        return findings;
    }
}
