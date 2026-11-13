package com.sme.cyberrisk.controller;

import com.sme.cyberrisk.service.AssetService;
import com.sme.cyberrisk.service.ComplianceService;
import com.sme.cyberrisk.service.ReportService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Controller
public class ReportController {

    private final ReportService reportService;
    private final AssetService assetService;
    private final ComplianceService complianceService;

    public ReportController(ReportService reportService, AssetService assetService, ComplianceService complianceService) {
        this.reportService = reportService;
        this.assetService = assetService;
        this.complianceService = complianceService;
    }

    @GetMapping("/report")
    public String executiveReport(Model model) {
        ReportService.ExecutiveDashboardStats stats = reportService.getDashboardStats();
        model.addAttribute("stats", stats);
        model.addAttribute("assets", assetService.getAllAssets());
        model.addAttribute("compliance", complianceService.getSummary());
        model.addAttribute("reportDate", LocalDateTime.now().format(DateTimeFormatter.ofPattern("MMMM dd, yyyy HH:mm")));
        return "report";
    }

    @GetMapping("/playbook")
    public String remediationPlaybook() {
        return "playbook";
    }
}
