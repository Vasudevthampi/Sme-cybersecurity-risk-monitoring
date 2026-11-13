package com.sme.cyberrisk.service;

import com.sme.cyberrisk.model.ComplianceItem;
import com.sme.cyberrisk.repository.ComplianceItemRepository;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class ComplianceService {

    private final ComplianceItemRepository complianceRepo;

    public ComplianceService(ComplianceItemRepository complianceRepo) {
        this.complianceRepo = complianceRepo;
    }

    public List<ComplianceItem> getAllItems() {
        return complianceRepo.findAll();
    }

    public ComplianceItem updateStatus(Long id, String newStatus) {
        ComplianceItem item = complianceRepo.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("Compliance item not found: " + id));
        item.setStatus(newStatus.toUpperCase());
        return complianceRepo.save(item);
    }

    public record ComplianceSummary(
        int totalItems,
        long implementedCount,
        long partialCount,
        long notImplementedCount,
        int overallScorePercentage,
        Map<String, Integer> categoryScores
    ) {}

    public ComplianceSummary getSummary() {
        List<ComplianceItem> all = complianceRepo.findAll();
        if (all.isEmpty()) {
            return new ComplianceSummary(0, 0, 0, 0, 0, Map.of());
        }

        long implemented = all.stream().filter(i -> "IMPLEMENTED".equalsIgnoreCase(i.getStatus())).count();
        long partial = all.stream().filter(i -> "PARTIAL".equalsIgnoreCase(i.getStatus())).count();
        long notImplemented = all.stream().filter(i -> "NOT_IMPLEMENTED".equalsIgnoreCase(i.getStatus())).count();

        int totalWeightedScore = 0;
        int maxPossibleWeightedScore = 0;

        Map<String, List<ComplianceItem>> grouped = all.stream()
            .collect(Collectors.groupingBy(ComplianceItem::getNistCategory));

        Map<String, Integer> categoryScores = new LinkedHashMap<>();

        for (Map.Entry<String, List<ComplianceItem>> entry : grouped.entrySet()) {
            String category = entry.getKey();
            List<ComplianceItem> items = entry.getValue();

            int catEarned = 0;
            int catMax = 0;

            for (ComplianceItem item : items) {
                int earnedMultiplier = "IMPLEMENTED".equalsIgnoreCase(item.getStatus()) ? 100 :
                                      "PARTIAL".equalsIgnoreCase(item.getStatus()) ? 50 : 0;
                catEarned += (earnedMultiplier * item.getWeight());
                catMax += (100 * item.getWeight());
            }

            int catPercent = catMax > 0 ? (int) Math.round(((double) catEarned / catMax) * 100) : 0;
            categoryScores.put(category, catPercent);

            totalWeightedScore += catEarned;
            maxPossibleWeightedScore += catMax;
        }

        int overallScore = maxPossibleWeightedScore > 0 ?
            (int) Math.round(((double) totalWeightedScore / maxPossibleWeightedScore) * 100) : 0;

        return new ComplianceSummary(
            all.size(),
            implemented,
            partial,
            notImplemented,
            overallScore,
            categoryScores
        );
    }
}
