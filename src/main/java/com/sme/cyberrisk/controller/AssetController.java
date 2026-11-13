package com.sme.cyberrisk.controller;

import com.sme.cyberrisk.model.Asset;
import com.sme.cyberrisk.model.AssetType;
import com.sme.cyberrisk.model.Criticality;
import com.sme.cyberrisk.repository.ScanResultRepository;
import com.sme.cyberrisk.service.AssetService;
import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/assets")
public class AssetController {

    private final AssetService assetService;
    private final ScanResultRepository scanRepo;

    public AssetController(AssetService assetService, ScanResultRepository scanRepo) {
        this.assetService = assetService;
        this.scanRepo = scanRepo;
    }

    @GetMapping
    public String listAssets(Model model) {
        model.addAttribute("assets", assetService.getAllAssets());
        model.addAttribute("newAsset", new Asset("", "", AssetType.DOMAIN, Criticality.MEDIUM, "IT", ""));
        model.addAttribute("assetTypes", AssetType.values());
        model.addAttribute("criticalities", Criticality.values());
        return "assets";
    }

    @PostMapping
    public String createAsset(@Valid @ModelAttribute("newAsset") Asset asset,
                              BindingResult result,
                              Model model,
                              RedirectAttributes redirectAttributes) {
        if (result.hasErrors()) {
            model.addAttribute("assets", assetService.getAllAssets());
            model.addAttribute("assetTypes", AssetType.values());
            model.addAttribute("criticalities", Criticality.values());
            return "assets";
        }

        Asset saved = assetService.saveAsset(asset);
        // Automatically perform initial scan on newly registered asset
        try {
            assetService.runScanOnAsset(saved.getId());
            redirectAttributes.addFlashAttribute("successMessage", "Asset '" + saved.getName() + "' added and initial security audit completed!");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("successMessage", "Asset registered. (Initial scan encountered notice: " + e.getMessage() + ")");
        }

        return "redirect:/assets";
    }

    @GetMapping("/{id}")
    public String assetDetail(@PathVariable Long id, Model model) {
        Asset asset = assetService.getAssetById(id)
            .orElseThrow(() -> new IllegalArgumentException("Invalid asset Id: " + id));
        model.addAttribute("asset", asset);
        model.addAttribute("scanHistory", scanRepo.findByAssetIdOrderByScanDateDesc(id));
        return "asset-detail";
    }

    @PostMapping("/{id}/delete")
    public String deleteAsset(@PathVariable Long id, RedirectAttributes redirectAttributes) {
        assetService.deleteAsset(id);
        redirectAttributes.addFlashAttribute("successMessage", "Asset deleted successfully.");
        return "redirect:/assets";
    }
}
