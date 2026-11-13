package com.sme.cyberrisk.model;

public enum Severity {
    CRITICAL("Critical", 25, "bg-red-100 text-red-800 border-red-300"),
    HIGH("High", 15, "bg-orange-100 text-orange-800 border-orange-300"),
    MEDIUM("Medium", 8, "bg-amber-100 text-amber-800 border-amber-300"),
    LOW("Low", 3, "bg-blue-100 text-blue-800 border-blue-300"),
    INFO("Info", 0, "bg-slate-100 text-slate-800 border-slate-300");

    private final String label;
    private final int penaltyScore;
    private final String badgeClass;

    Severity(String label, int penaltyScore, String badgeClass) {
        this.label = label;
        this.penaltyScore = penaltyScore;
        this.badgeClass = badgeClass;
    }

    public String getLabel() {
        return label;
    }

    public int getPenaltyScore() {
        return penaltyScore;
    }

    public String getBadgeClass() {
        return badgeClass;
    }
}
