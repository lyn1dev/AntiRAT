package com.antirat.scanner;

public enum ThreatCategory {
    WEBHOOK_C2("Exfiltration Endpoint (Webhook / C2)"),
    STEALER_TARGET("Token / Credential Target"),
    PROCESS_EXECUTION("Process Spawning / Shell Execution"),
    NATIVE_LIBRARY_LOAD("Native Library Injection");

    private final String description;

    ThreatCategory(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }
}
