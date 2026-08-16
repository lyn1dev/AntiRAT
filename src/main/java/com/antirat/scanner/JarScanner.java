package com.antirat.scanner;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * High-performance static scanner that inspects mod jars before execution
 * for Discord webhooks, credential theft targets, shell droppers, and native loaders.
 */
public final class JarScanner {

    private static final List<Signature> SIGNATURES = List.of(
            // Webhooks & Exfiltration
            new Signature(ThreatCategory.WEBHOOK_C2, "discord.com/api/webhooks"),
            new Signature(ThreatCategory.WEBHOOK_C2, "discordapp.com/api/webhooks"),
            new Signature(ThreatCategory.WEBHOOK_C2, "api.telegram.org/bot"),
            new Signature(ThreatCategory.WEBHOOK_C2, "webhook.site/"),
            new Signature(ThreatCategory.WEBHOOK_C2, "pastebin.com/raw/"),
            new Signature(ThreatCategory.WEBHOOK_C2, "hastebin.com/raw/"),
            new Signature(ThreatCategory.WEBHOOK_C2, "transfer.sh/"),
            new Signature(ThreatCategory.WEBHOOK_C2, "gofile.io/"),
            new Signature(ThreatCategory.WEBHOOK_C2, "ngrok-free.app"),

            // Stealer Targets
            new Signature(ThreatCategory.STEALER_TARGET, "launcher_accounts.json"),
            new Signature(ThreatCategory.STEALER_TARGET, "launcher_profiles.json"),
            new Signature(ThreatCategory.STEALER_TARGET, ".minecraft/launcher_accounts"),
            new Signature(ThreatCategory.STEALER_TARGET, "Roaming/.minecraft"),
            new Signature(ThreatCategory.STEALER_TARGET, "Local/Google/Chrome"),
            new Signature(ThreatCategory.STEALER_TARGET, "AppData/Local/BraveSoftware"),
            new Signature(ThreatCategory.STEALER_TARGET, "XBL3.0"),
            new Signature(ThreatCategory.STEALER_TARGET, "token.dat"),

            // Process Droppers
            new Signature(ThreatCategory.PROCESS_EXECUTION, "java/lang/ProcessBuilder"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "powershell -"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "cmd.exe /c")
    );

    private record Signature(ThreatCategory category, String pattern) {
    }

    private JarScanner() {
    }

    /**
     * Scans all .jar files in the specified mods directory.
     *
     * @param modsDir directory containing mods
     * @return list of scan reports that contain detected threats
     */
    public static List<ScanReport> scanModsDirectory(Path modsDir) {
        if (modsDir == null || !Files.isDirectory(modsDir)) {
            return Collections.emptyList();
        }
        List<ScanReport> reportsWithThreats = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(modsDir, "*.jar")) {
            for (Path jarPath : stream) {
                if (Files.isRegularFile(jarPath)) {
                    ScanReport report = scanJar(jarPath);
                    if (report.hasThreats()) {
                        reportsWithThreats.add(report);
                    }
                }
            }
        } catch (IOException e) {
            // best effort scan
        }
        return reportsWithThreats;
    }

    /**
     * Scans a single jar file.
     *
     * @param jarPath path to the jar file
     * @return ScanReport containing all detected findings
     */
    public static ScanReport scanJar(Path jarPath) {
        String fileName = jarPath.getFileName() != null ? jarPath.getFileName().toString() : jarPath.toString();
        List<ScanFinding> findings = new ArrayList<>();
        Set<String> deduplication = new HashSet<>();

        try (InputStream fis = Files.newInputStream(jarPath);
             BufferedInputStream bis = new BufferedInputStream(fis);
             ZipInputStream zis = new ZipInputStream(bis)) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String entryName = entry.getName();
                if (entryName.endsWith(".class")) {
                    // Ignore AntiRAT's own classes
                    if (entryName.startsWith("com/antirat/")) {
                        continue;
                    }
                    List<String> strings = ClassConstantPoolReader.extractUtf8Strings(zis);
                    analyzeClassStrings(entryName, strings, findings, deduplication);
                } else if (entryName.endsWith(".jar") || entryName.endsWith(".zip")) {
                    // Nested jar scan
                    try (ZipInputStream nestedZis = new ZipInputStream(zis)) {
                        ZipEntry nestedEntry;
                        while ((nestedEntry = nestedZis.getNextEntry()) != null) {
                            String nestedName = nestedEntry.getName();
                            if (nestedName.endsWith(".class") && !nestedName.startsWith("com/antirat/")) {
                                List<String> nestedStrings = ClassConstantPoolReader.extractUtf8Strings(nestedZis);
                                analyzeClassStrings(entryName + "!" + nestedName, nestedStrings, findings, deduplication);
                            }
                        }
                    } catch (Exception ignored) {
                        // ignore malformed nested entries
                    }
                }
            }
        } catch (IOException e) {
            // Cannot open jar
        }
        return new ScanReport(jarPath, fileName, findings);
    }

    private static void analyzeClassStrings(String className, List<String> strings,
                                            List<ScanFinding> findings, Set<String> deduplication) {
        for (String str : strings) {
            if (str == null || str.length() < 4) {
                continue;
            }
            String lower = str.toLowerCase(Locale.ROOT);
            for (Signature sig : SIGNATURES) {
                if (lower.contains(sig.pattern.toLowerCase(Locale.ROOT))) {
                    String dedupKey = className + "|" + sig.category + "|" + str;
                    if (deduplication.add(dedupKey)) {
                        findings.add(new ScanFinding(
                                className.replace('/', '.').replace(".class", ""),
                                sig.category,
                                sig.pattern,
                                truncate(str, 120)
                        ));
                    }
                }
            }
        }
    }

    private static String truncate(String s, int maxLen) {
        if (s.length() <= maxLen) {
            return s;
        }
        return s.substring(0, maxLen) + "...";
    }
}
