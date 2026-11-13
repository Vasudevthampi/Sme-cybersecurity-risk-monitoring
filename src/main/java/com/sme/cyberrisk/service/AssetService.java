package com.sme.cyberrisk.service;

import com.sme.cyberrisk.model.*;
import com.sme.cyberrisk.repository.AssetRepository;
import com.sme.cyberrisk.repository.ScanResultRepository;
import com.sme.cyberrisk.service.scanner.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Service
public class AssetService {

    private final AssetRepository assetRepo;
    private final ScanResultRepository scanRepo;
    private final NetworkPortScanner portScanner;
    private final SslTlsAuditor sslAuditor;
    private final HttpHeaderAuditor headerAuditor;
    private final DnsEmailAuditor dnsAuditor;
    private final CveMatcher cveMatcher;
    private final RiskScoringService riskScoringService;

    public AssetService(
        AssetRepository assetRepo,
        ScanResultRepository scanRepo,
        NetworkPortScanner portScanner,
        SslTlsAuditor sslAuditor,
        HttpHeaderAuditor headerAuditor,
        DnsEmailAuditor dnsAuditor,
        CveMatcher cveMatcher,
        RiskScoringService riskScoringService
    ) {
        this.assetRepo = assetRepo;
        this.scanRepo = scanRepo;
        this.portScanner = portScanner;
        this.sslAuditor = sslAuditor;
        this.headerAuditor = headerAuditor;
        this.dnsAuditor = dnsAuditor;
        this.cveMatcher = cveMatcher;
        this.riskScoringService = riskScoringService;
    }

    public List<Asset> getAllAssets() {
        return assetRepo.findAll();
    }

    public Optional<Asset> getAssetById(Long id) {
        return assetRepo.findById(id);
    }

    public Asset saveAsset(Asset asset) {
        return assetRepo.save(asset);
    }

    public void deleteAsset(Long id) {
        assetRepo.deleteById(id);
    }

    @Transactional
    public ScanResult runScanOnAsset(Long assetId) {
        Asset asset = assetRepo.findById(assetId)
            .orElseThrow(() -> new IllegalArgumentException("Asset not found with ID: " + assetId));

        long startTime = System.currentTimeMillis();
        String host = asset.getCleanTargetHost();

        ScanResult scan = new ScanResult();
        scan.setAsset(asset);
        scan.setScanDate(LocalDateTime.now());

        List<Finding> allFindings = new ArrayList<>();

        // 1. Safe Network Port Scan
        NetworkPortScanner.ScanReport portReport = portScanner.scanHost(host);
        scan.setPortsScanned(portReport.scannedCount());
        scan.setOpenPorts(portReport.openPorts().isEmpty() ? "None Open" :
            portReport.openPorts().stream().map(String::valueOf).reduce((a, b) -> a + ", " + b).orElse(""));
        for (Finding f : portReport.findings()) {
            scan.addFinding(f);
            allFindings.add(f);
        }

        // 2. SSL/TLS Audit (Check port 443 if open or web asset)
        boolean hasHttps = portReport.openPorts().contains(443) || asset.getType() == AssetType.DOMAIN || asset.getType() == AssetType.WEB_APP;
        if (hasHttps) {
            SslTlsAuditor.SslReport sslReport = sslAuditor.inspect(host, 443);
            scan.setSslValid(sslReport.valid());
            scan.setSslDaysRemaining(sslReport.daysRemaining());
            scan.setSslIssuer(sslReport.issuer());
            scan.setSslProtocol(sslReport.protocol());
            for (Finding f : sslReport.findings()) {
                scan.addFinding(f);
                allFindings.add(f);
            }
        } else {
            scan.setSslValid(false);
            scan.setSslDaysRemaining(0);
            scan.setSslIssuer("N/A");
            scan.setSslProtocol("N/A");
        }

        // 3. HTTP Headers Audit
        boolean hasWeb = portReport.openPorts().contains(80) || hasHttps;
        String detectedServerBanner = "None";
        if (hasWeb) {
            HttpHeaderAuditor.HeaderReport headerReport = headerAuditor.auditHeaders(host);
            scan.setMissingHeaders(headerReport.missingHeaders().isEmpty() ? "All Core Headers Present" :
                String.join(", ", headerReport.missingHeaders()));
            detectedServerBanner = headerReport.serverBanner();
            for (Finding f : headerReport.findings()) {
                scan.addFinding(f);
                allFindings.add(f);
            }
        } else {
            scan.setMissingHeaders("N/A (No Web Port Open)");
        }

        // 4. DNS Email Security (SPF & DMARC)
        if (asset.getType() == AssetType.DOMAIN || (!host.matches("^[0-9.]+$") && !host.contains("localhost"))) {
            DnsEmailAuditor.EmailReport emailReport = dnsAuditor.auditDomain(host);
            scan.setSpfRecord(emailReport.spfRecord());
            scan.setDmarcRecord(emailReport.dmarcRecord());
            scan.setEmailSpoofable(emailReport.spoofable());
            for (Finding f : emailReport.findings()) {
                scan.addFinding(f);
                allFindings.add(f);
            }
        } else {
            scan.setSpfRecord("N/A (IP Address)");
            scan.setDmarcRecord("N/A (IP Address)");
            scan.setEmailSpoofable(false);
        }

        // 5. CVE Matcher
        List<Finding> cveFindings = cveMatcher.matchBanners(detectedServerBanner, portReport.openPorts());
        for (Finding f : cveFindings) {
            scan.addFinding(f);
            allFindings.add(f);
        }

        // 6. Risk Scoring
        RiskScoringService.RiskEvaluation eval = riskScoringService.calculateAssetRisk(allFindings, asset.getCriticality());
        scan.setRiskScore(eval.riskScore());
        scan.setRiskLevel(eval.riskLevel());
        scan.setScanDurationMs(System.currentTimeMillis() - startTime);

        long criticalCount = allFindings.stream().filter(f -> f.getSeverity() == Severity.CRITICAL).count();
        long highCount = allFindings.stream().filter(f -> f.getSeverity() == Severity.HIGH).count();
        scan.setSummary(String.format("Audit completed in %d ms. Found %d issues (%d critical, %d high). Risk Level: %s (Score %d/100).",
            scan.getScanDurationMs(), allFindings.size(), criticalCount, highCount, eval.riskLevel(), eval.riskScore()));

        // Save scan and update asset
        ScanResult savedScan = scanRepo.save(scan);

        asset.setLastScanDate(savedScan.getScanDate());
        asset.setCurrentRiskScore(eval.riskScore());
        asset.setCurrentRiskLevel(eval.riskLevel());
        assetRepo.save(asset);

        return savedScan;
    }

    public List<ScanResult> runAllScans() {
        List<Asset> active = assetRepo.findByActiveTrue();
        List<ScanResult> results = new ArrayList<>();
        for (Asset a : active) {
            results.add(runScanOnAsset(a.getId()));
        }
        return results;
    }
}
