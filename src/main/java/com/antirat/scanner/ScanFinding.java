package com.antirat.scanner;

/**
 * Represents a single security issue detected in a class during static scanning.
 */
public record ScanFinding(
        String className,
        ThreatCategory category,
        String matchedSignature,
        String sampleContent
) {
    @Override
    public String toString() {
        return "[" + category + "] in " + className + " -> matched '" + matchedSignature + "' (context: " + sampleContent + ")";
    }
}
