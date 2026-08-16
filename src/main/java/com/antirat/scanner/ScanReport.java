package com.antirat.scanner;

import java.nio.file.Path;
import java.util.List;

/**
 * Summary of static scanning findings for a specific mod jar.
 */
public record ScanReport(
        Path jarPath,
        String fileName,
        List<ScanFinding> findings
) {
    public boolean hasThreats() {
        return findings != null && !findings.isEmpty();
    }
}
