package com.sme.cyberrisk.controller;

import com.sme.cyberrisk.model.Asset;
import com.sme.cyberrisk.model.ScanResult;
import com.sme.cyberrisk.service.AssetService;
import com.sme.cyberrisk.service.ComplianceService;
import com.sme.cyberrisk.service.ReportService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1")
public class ApiController {

    private final ReportService reportService;
    private final AssetService assetService;
    private final ComplianceService complianceService;

    public ApiController(ReportService reportService, AssetService assetService, ComplianceService complianceService) {
        this.reportService = reportService;
        this.assetService = assetService;
        this.complianceService = complianceService;
    }

    @GetMapping("/stats")
    public ResponseEntity<ReportService.ExecutiveDashboardStats> getStats() {
        return ResponseEntity.ok(reportService.getDashboardStats());
    }

    @GetMapping("/assets")
    public ResponseEntity<List<Asset>> getAssets() {
        return ResponseEntity.ok(assetService.getAllAssets());
    }

    @PostMapping("/scan/{assetId}")
    public ResponseEntity<ScanResult> runScan(@PathVariable Long assetId) {
        return ResponseEntity.ok(assetService.runScanOnAsset(assetId));
    }

    @GetMapping("/compliance")
    public ResponseEntity<ComplianceService.ComplianceSummary> getCompliance() {
        return ResponseEntity.ok(complianceService.getSummary());
    }
}
