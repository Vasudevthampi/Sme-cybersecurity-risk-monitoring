package com.sme.cyberrisk.model;

public enum Criticality {
    CRITICAL("Critical (Core Business/Revenue/DB)", 1.5),
    HIGH("High (Customer Facing / Key Services)", 1.25),
    MEDIUM("Medium (Internal Tools / Operational)", 1.0),
    LOW("Low (Development / Non-Essential)", 0.75);

    private final String label;
    private final double multiplier;

    Criticality(String label, double multiplier) {
        this.label = label;
        this.multiplier = multiplier;
    }

    public String getLabel() {
        return label;
    }

    public double getMultiplier() {
        return multiplier;
    }
}
