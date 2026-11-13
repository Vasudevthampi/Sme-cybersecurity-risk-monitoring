package com.sme.cyberrisk.controller;

import com.sme.cyberrisk.model.ScanResult;
import com.sme.cyberrisk.repository.ScanResultRepository;
import com.sme.cyberrisk.service.AssetService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/scan")
public class ScanController {

    private final AssetService assetService;
    private final ScanResultRepository scanRepo;

    public ScanController(AssetService assetService, ScanResultRepository scanRepo) {
        this.assetService = assetService;
        this.scanRepo = scanRepo;
    }

    @PostMapping("/run/{assetId}")
    public String runScan(@PathVariable Long assetId, RedirectAttributes redirectAttributes) {
        try {
            ScanResult result = assetService.runScanOnAsset(assetId);
            redirectAttributes.addFlashAttribute("successMessage",
                "Audit finished for " + result.getAsset().getName() + "! Score: " + result.getRiskScore() + " (" + result.getRiskLevel() + " Risk)");
            return "redirect:/assets/" + assetId;
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Scan error: " + e.getMessage());
            return "redirect:/assets/" + assetId;
        }
    }

    @PostMapping("/run-all")
    public String runAllScans(RedirectAttributes redirectAttributes) {
        try {
            var results = assetService.runAllScans();
            redirectAttributes.addFlashAttribute("successMessage",
                "Company-wide security audit completed across " + results.size() + " active assets!");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Batch scan error: " + e.getMessage());
        }
        return "redirect:/dashboard";
    }

    @GetMapping("/result/{id}")
    public String viewScanResult(@PathVariable Long id, Model model) {
        ScanResult result = scanRepo.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("Scan result not found: " + id));
        model.addAttribute("scan", result);
        return "scan-run";
    }
}
