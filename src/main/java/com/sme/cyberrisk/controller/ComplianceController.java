package com.sme.cyberrisk.controller;

import com.sme.cyberrisk.service.ComplianceService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/compliance")
public class ComplianceController {

    private final ComplianceService complianceService;

    public ComplianceController(ComplianceService complianceService) {
        this.complianceService = complianceService;
    }

    @GetMapping
    public String viewCompliance(Model model) {
        model.addAttribute("items", complianceService.getAllItems());
        model.addAttribute("summary", complianceService.getSummary());
        return "compliance";
    }

    @PostMapping("/update")
    public String updateStatus(@RequestParam("id") Long id,
                               @RequestParam("status") String status,
                               RedirectAttributes redirectAttributes) {
        complianceService.updateStatus(id, status);
        redirectAttributes.addFlashAttribute("successMessage", "Compliance control updated. Risk scores recalculated.");
        return "redirect:/compliance";
    }
}
