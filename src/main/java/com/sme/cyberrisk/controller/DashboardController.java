package com.sme.cyberrisk.controller;

import com.sme.cyberrisk.model.Asset;
import com.sme.cyberrisk.model.AssetType;
import com.sme.cyberrisk.model.Criticality;
import com.sme.cyberrisk.service.AssetService;
import com.sme.cyberrisk.service.ComplianceService;
import com.sme.cyberrisk.service.ReportService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    private final ReportService reportService;
    private final AssetService assetService;
    private final ComplianceService complianceService;

    public DashboardController(ReportService reportService, AssetService assetService, ComplianceService complianceService) {
        this.reportService = reportService;
        this.assetService = assetService;
        this.complianceService = complianceService;
    }

    @GetMapping({"/", "/dashboard"})
    public String dashboard(Model model) {
        ReportService.ExecutiveDashboardStats stats = reportService.getDashboardStats();
        model.addAttribute("stats", stats);
        model.addAttribute("assets", assetService.getAllAssets());
        model.addAttribute("compliance", complianceService.getSummary());
        model.addAttribute("newAsset", new Asset("", "", AssetType.DOMAIN, Criticality.MEDIUM, "IT", ""));
        model.addAttribute("assetTypes", AssetType.values());
        model.addAttribute("criticalities", Criticality.values());
        return "dashboard";
    }
}
