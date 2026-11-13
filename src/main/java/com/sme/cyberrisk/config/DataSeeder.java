package com.sme.cyberrisk.config;

import com.sme.cyberrisk.model.*;
import com.sme.cyberrisk.repository.*;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;

@Component
public class DataSeeder implements CommandLineRunner {

    private final AssetRepository assetRepo;
    private final ComplianceItemRepository complianceRepo;
    private final VulnerabilityInfoRepository vulnRepo;
    private final ScanResultRepository scanRepo;

    public DataSeeder(
        AssetRepository assetRepo,
        ComplianceItemRepository complianceRepo,
        VulnerabilityInfoRepository vulnRepo,
        ScanResultRepository scanRepo
    ) {
        this.assetRepo = assetRepo;
        this.complianceRepo = complianceRepo;
        this.vulnRepo = vulnRepo;
        this.scanRepo = scanRepo;
    }

    @Override
    public void run(String... args) {
        if (complianceRepo.count() == 0) {
            seedComplianceItems();
        }
        if (vulnRepo.count() == 0) {
            seedVulnerabilities();
        }
        if (assetRepo.count() == 0) {
            seedSampleAssetsAndScans();
        }
    }

    private void seedComplianceItems() {
        List<ComplianceItem> items = List.of(
            // IDENTIFY
            new ComplianceItem("IDENTIFY", "ID.AM-1", "Physical & Digital Asset Inventory",
                "Maintain an up-to-date catalog of all company workstations, mobile devices, servers, and cloud accounts.",
                "IMPLEMENTED", 4, "Use automated discovery or a centralized inventory spreadsheet updated monthly."),
            new ComplianceItem("IDENTIFY", "ID.RA-1", "Vulnerability & Threat Risk Assessments",
                "Perform scheduled vulnerability scanning and risk assessments of company public-facing assets.",
                "PARTIAL", 4, "Use the SME Cyber Risk Monitor to audit assets monthly."),
            new ComplianceItem("IDENTIFY", "ID.SC-1", "Supply Chain & Third-Party Vendor Risk",
                "Evaluate cybersecurity requirements for external SaaS providers and software vendors.",
                "NOT_IMPLEMENTED", 3, "Verify SOC2 or ISO 27001 reports from vendors handling company data."),

            // PROTECT
            new ComplianceItem("PROTECT", "PR.AC-1", "Multi-Factor Authentication (MFA) Enforced",
                "Enforce MFA across all employee emails, remote VPN, cloud portals, and administrative accounts.",
                "PARTIAL", 5, "Activate MFA in Google Workspace / Microsoft 365. Avoid SMS-based 2FA where possible; use authenticator apps."),
            new ComplianceItem("PROTECT", "PR.DS-1", "3-2-1 Automated Immutable Data Backups",
                "Maintain 3 copies of business-critical data on 2 different media types, with 1 copy stored offsite/cloud and immutable against ransomware.",
                "IMPLEMENTED", 5, "Ensure cloud backups have versioning and deletion protection enabled."),
            new ComplianceItem("PROTECT", "PR.AT-1", "Employee Cybersecurity & Phishing Awareness",
                "Conduct simulated phishing tests and security hygiene workshops for all staff at least quarterly.",
                "NOT_IMPLEMENTED", 4, "Train employees never to authorize invoice changes without verbal phone verification."),
            new ComplianceItem("PROTECT", "PR.IP-1", "Perimeter Network Defense & Firewall Rules",
                "Block inbound risky ports (RDP 3389, SMB 445) at perimeter firewalls.",
                "IMPLEMENTED", 5, "Inspect perimeter router/firewall rules; strictly disable Universal Plug and Play (UPnP)."),

            // DETECT
            new ComplianceItem("DETECT", "DE.CM-1", "Endpoint Antivirus & EDR Protection",
                "Deploy managed Endpoint Detection & Response (EDR) or updated antivirus on all employee laptops.",
                "IMPLEMENTED", 4, "Ensure Windows Defender or enterprise EDR is centrally monitored and auto-updating."),
            new ComplianceItem("DETECT", "DE.AE-1", "Centralized Audit Logging & Alerts",
                "Log sign-in attempts, administrative privilege escalations, and unusual file deletion activity.",
                "NOT_IMPLEMENTED", 3, "Enable audit log retention in cloud suite for at least 90 days."),

            // RESPOND
            new ComplianceItem("RESPOND", "RS.RP-1", "Documented Incident Response Plan",
                "Have a written step-by-step incident response playbook with designated lead and emergency IT/legal contacts.",
                "PARTIAL", 4, "Create a 1-page emergency contact sheet and store printed copies in case IT is down."),
            new ComplianceItem("RESPOND", "RS.CO-1", "Customer & Breach Notification Readiness",
                "Prepare communication templates and legal notification protocols in case of a customer data breach.",
                "NOT_IMPLEMENTED", 3, "Understand local data privacy disclosure obligations (e.g. GDPR, CCPA)."),

            // RECOVER
            new ComplianceItem("RECOVER", "RC.RP-1", "Disaster Recovery & Tested Restore",
                "Conduct a simulated data restoration drill at least every 6 months to verify backups can actually be restored.",
                "PARTIAL", 5, "Conduct a test restore of the main accounting or database backup to a sandbox machine."),
            new ComplianceItem("RECOVER", "RC.CO-1", "Cyber Insurance Policy Active",
                "Maintain a current cyber liability insurance policy covering ransomware, extortion, and business interruption.",
                "IMPLEMENTED", 3, "Verify policy coverage terms and ensure required security controls (MFA) are verified.")
        );
        complianceRepo.saveAll(items);
    }

    private void seedVulnerabilities() {
        List<VulnerabilityInfo> vulns = List.of(
            new VulnerabilityInfo("CVE-2024-6387", "OpenSSH", "([89]\\.[0-4]|8\\.[5-9])", 8.1, Severity.HIGH,
                "regreSSHion: Remote Code Execution in OpenSSH server",
                "A signal handler race condition vulnerability in OpenSSH allows unauthenticated remote code execution as root on glibc-based Linux systems.",
                "Upgrade OpenSSH to version 9.8p1 or newer. If unable to upgrade immediately, set 'LoginGraceTime 0' in sshd_config."),

            new VulnerabilityInfo("CVE-2021-44228", "Log4j", ".*", 10.0, Severity.CRITICAL,
                "Log4Shell: Unauthenticated Remote Code Execution in Log4j",
                "JNDI lookup features do not protect against attacker-controlled LDAP and other JNDI related endpoints, allowing instant remote code execution.",
                "Update Log4j to version 2.17.1 or higher. Alternatively set system property log4j2.formatMsgNoLookups=true."),

            new VulnerabilityInfo("CVE-2021-41773", "Apache", "2\\.4\\.(49|50)", 7.5, Severity.HIGH,
                "Apache HTTP Server Path Traversal & File Disclosure",
                "A path traversal attack allows attackers to map URLs to files outside the document root, potentially exposing sensitive configuration files.",
                "Update Apache HTTP Server to version 2.4.51 or higher."),

            new VulnerabilityInfo("CVE-2019-0708", "RDP", ".*", 9.8, Severity.CRITICAL,
                "BlueKeep: Remote Desktop Protocol Pre-Authentication RCE",
                "A remote code execution vulnerability exists in Remote Desktop Services when an unauthenticated attacker connects using RDP and sends specially crafted requests.",
                "Immediately close port 3389 to the public internet. Apply Microsoft patch KB4499175 and enable Network Level Authentication (NLA)."),

            new VulnerabilityInfo("CVE-2017-0144", "SMB", ".*", 9.8, Severity.CRITICAL,
                "EternalBlue: Windows SMBv1 Remote Code Execution",
                "A flaw in SMBv1 handling allows remote attackers to execute code via crafted packets. Exploited worldwide by WannaCry and NotPetya ransomware.",
                "Completely disable SMBv1 and block port 445 at external perimeter firewall. Apply Microsoft MS17-010.")
        );
        vulnRepo.saveAll(vulns);
    }

    private void seedSampleAssetsAndScans() {
        // Asset 1: Primary Corporate Web & Domain
        Asset asset1 = new Asset(
            "Corporate Web & Domain",
            "example.com",
            AssetType.DOMAIN,
            Criticality.HIGH,
            "Marketing & Sales",
            "Main customer-facing corporate domain, email routing, and public website."
        );
        asset1.setLastScanDate(LocalDateTime.now().minusHours(2));
        asset1.setCurrentRiskScore(42);
        asset1.setCurrentRiskLevel("Medium");
        assetRepo.save(asset1);

        ScanResult scan1 = new ScanResult();
        scan1.setAsset(asset1);
        scan1.setScanDate(LocalDateTime.now().minusHours(2));
        scan1.setScanDurationMs(1850);
        scan1.setPortsScanned(15);
        scan1.setOpenPorts("80, 443");
        scan1.setSslValid(true);
        scan1.setSslDaysRemaining(45);
        scan1.setSslIssuer("CN=DigiCert Global Root CA");
        scan1.setSslProtocol("TLSv1.3");
        scan1.setMissingHeaders("Strict-Transport-Security, Content-Security-Policy");
        scan1.setSpfRecord("v=spf1 include:_spf.google.com ~all");
        scan1.setDmarcRecord("v=DMARC1; p=none; rua=mailto:dmarc@example.com");
        scan1.setEmailSpoofable(true);
        scan1.setRiskScore(42);
        scan1.setRiskLevel("Medium");
        scan1.setSummary("Audit completed. SSL is valid (45 days remaining). Missing HSTS and CSP headers. DMARC policy is set to 'p=none', leaving email spoofing risk open.");

        scan1.addFinding(new Finding(FindingCategory.HTTP_HEADERS, Severity.MEDIUM,
            "Missing Strict-Transport-Security (HSTS) Header",
            "Without HSTS, attackers on the network can downgrade user sessions to unencrypted HTTP.",
            "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", "10 mins"));

        scan1.addFinding(new Finding(FindingCategory.HTTP_HEADERS, Severity.MEDIUM,
            "Missing Content-Security-Policy (CSP) Header",
            "Absence of CSP exposes the website to Cross-Site Scripting (XSS) and rogue script injection.",
            "Define a restrictive Content-Security-Policy directive in web server config.", "25 mins"));

        scan1.addFinding(new Finding(FindingCategory.EMAIL_SECURITY, Severity.MEDIUM,
            "DMARC Policy Set to 'p=none' (Monitoring Only)",
            "DMARC is not enforcing quarantine or rejection of spoofed emails. Phishing attacks impersonating your domain will still succeed.",
            "Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'.", "15 mins"));

        scanRepo.save(scan1);

        // Asset 2: Legacy Remote Gateway with Exposed RDP (High Risk Alert!)
        Asset asset2 = new Asset(
            "Branch Office Gateway",
            "192.168.1.100",
            AssetType.INTERNAL_HOST,
            Criticality.CRITICAL,
            "Operations & IT",
            "Branch office perimeter router and remote administrative desktop entry."
        );
        asset2.setLastScanDate(LocalDateTime.now().minusHours(5));
        asset2.setCurrentRiskScore(85);
        asset2.setCurrentRiskLevel("Critical");
        assetRepo.save(asset2);

        ScanResult scan2 = new ScanResult();
        scan2.setAsset(asset2);
        scan2.setScanDate(LocalDateTime.now().minusHours(5));
        scan2.setScanDurationMs(2100);
        scan2.setPortsScanned(15);
        scan2.setOpenPorts("80, 445, 3389");
        scan2.setSslValid(false);
        scan2.setSslDaysRemaining(0);
        scan2.setSslIssuer("N/A");
        scan2.setSslProtocol("N/A");
        scan2.setMissingHeaders("N/A (Internal Gateway)");
        scan2.setSpfRecord("N/A (IP Address)");
        scan2.setDmarcRecord("N/A (IP Address)");
        scan2.setEmailSpoofable(false);
        scan2.setRiskScore(85);
        scan2.setRiskLevel("Critical");
        scan2.setSummary("CRITICAL ALERT: Exposed Remote Desktop (port 3389) and SMB (port 445) detected! Primary vector for ransomware infiltration.");

        scan2.addFinding(new Finding(FindingCategory.NETWORK_PORTS, Severity.CRITICAL,
            "Exposed Port 3389 (Remote Desktop Protocol - RDP)",
            "Directly exposed RDP is the single most common entry point exploited by ransomware syndicates against SMEs.",
            "Immediately close port 3389 at firewall. Require an encrypted WireGuard/OpenVPN tunnel before accessing desktop.", "10 mins"));

        scan2.addFinding(new Finding(FindingCategory.NETWORK_PORTS, Severity.CRITICAL,
            "Exposed Port 445 (SMB / Active Directory Sharing)",
            "Port 445 exposed to network. This is the primary lateral movement vector used by WannaCry and ransomware wipers.",
            "Block port 445 immediately at perimeter. Only allow SMB over internal LAN or secure site-to-site VPN.", "5 mins"));

        scanRepo.save(scan2);

        // Asset 3: Customer Portal (Good Health)
        Asset asset3 = new Asset(
            "Customer Support Portal",
            "support.sme-techlogistics.com",
            AssetType.WEB_APP,
            Criticality.MEDIUM,
            "Customer Success",
            "Zendesk/Helpdesk customer ticket portal."
        );
        asset3.setLastScanDate(LocalDateTime.now().minusDays(1));
        asset3.setCurrentRiskScore(12);
        asset3.setCurrentRiskLevel("Low");
        assetRepo.save(asset3);

        ScanResult scan3 = new ScanResult();
        scan3.setAsset(asset3);
        scan3.setScanDate(LocalDateTime.now().minusDays(1));
        scan3.setScanDurationMs(1200);
        scan3.setPortsScanned(15);
        scan3.setOpenPorts("443");
        scan3.setSslValid(true);
        scan3.setSslDaysRemaining(112);
        scan3.setSslIssuer("CN=Let's Encrypt Authority X3");
        scan3.setSslProtocol("TLSv1.3");
        scan3.setMissingHeaders("Referrer-Policy");
        scan3.setSpfRecord("v=spf1 include:_spf.google.com ~all");
        scan3.setDmarcRecord("v=DMARC1; p=reject; rua=mailto:dmarc@example.com");
        scan3.setEmailSpoofable(false);
        scan3.setRiskScore(12);
        scan3.setRiskLevel("Low");
        scan3.setSummary("Audited successfully. Strong security posture: TLS 1.3 enforced, DMARC reject policy active, valid SSL cert with 112 days remaining.");

        scan3.addFinding(new Finding(FindingCategory.HTTP_HEADERS, Severity.LOW,
            "Missing Referrer-Policy Header",
            "Referrer header may leak full URLs containing sensitive parameters to external links.",
            "Add HTTP header: Referrer-Policy: strict-origin-when-cross-origin", "5 mins"));

        scanRepo.save(scan3);
    }
}
