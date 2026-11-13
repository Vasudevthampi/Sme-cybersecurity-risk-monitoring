package com.sme.cyberrisk.model;

public enum AssetType {
    DOMAIN("Domain / Website"),
    IP_ADDRESS("Server IP Address"),
    WEB_APP("Web Application"),
    INTERNAL_HOST("Internal Host / Workstation"),
    CLOUD_SERVICE("Cloud Service / API");

    private final String displayName;

    AssetType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
