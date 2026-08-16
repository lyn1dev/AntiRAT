package com.antirat.scanner;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * High-performance static scanner that inspects mod jars before execution
 * for Discord webhooks, credential theft targets, shell droppers, and native loaders.
 *
 * Designed with strict precision to prevent false positives in legitimate modpacks.
 */
public final class JarScanner {

    private static final Pattern BASE64_PATTERN = Pattern.compile("[A-Za-z0-9+/=]{16,}|[A-Za-z0-9_-]{16,}");
    private static final Pattern HEX_PATTERN = Pattern.compile("^(?:[0-9a-fA-F]{2}){8,}$");

    private static final Set<String> EXECUTABLE_EXTENSIONS = Set.of(
            ".dll", ".exe", ".so", ".dylib", ".vbs", ".bat", ".cmd", ".ps1", ".scr", ".pif"
    );

    // Whitelisted package paths for legitimate library native binaries (e.g. FlatLaf, LWJGL, SQLite, JNA)
    private static final List<String> LEGITIMATE_NATIVE_PREFIXES = List.of(
            "com/formdev/flatlaf/",
            "org/lwjgl/",
            "org/sqlite/",
            "com/sun/jna/",
            "oshi/",
            "net/java/games/input/",
            "ca/weblite/objc/",
            "natives/"
    );

    private static final List<Signature> SIGNATURES = List.of(
            // Webhooks & Exfiltration
            new Signature(ThreatCategory.WEBHOOK_C2, "discord.com/api/webhooks"),
            new Signature(ThreatCategory.WEBHOOK_C2, "discordapp.com/api/webhooks"),
            new Signature(ThreatCategory.WEBHOOK_C2, "api.telegram.org/bot"),
            new Signature(ThreatCategory.WEBHOOK_C2, "webhook.site"),
            new Signature(ThreatCategory.WEBHOOK_C2, "pastebin.com/raw/"),
            new Signature(ThreatCategory.WEBHOOK_C2, "hastebin.com/raw/"),
            new Signature(ThreatCategory.WEBHOOK_C2, "transfer.sh"),
            new Signature(ThreatCategory.WEBHOOK_C2, "gofile.io"),
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

            // Malicious Shell Dropper Commands (specific to droppers, not standard process builders)
            new Signature(ThreatCategory.PROCESS_EXECUTION, "powershell -enc"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "powershell -executionpolicy bypass"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "powershell -exec bypass"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "powershell -w hidden"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "powershell -windowstyle hidden"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "powershell -command"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "powershell.exe -command"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "cmd.exe /c start /b"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "cmd.exe /c curl "),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "cmd.exe /c bitsadmin"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "certutil -urlcache"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "iex(new-object net.webclient)"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "iex (new-object net.webclient)"),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "/bin/bash -c curl "),
            new Signature(ThreatCategory.PROCESS_EXECUTION, "/bin/sh -c curl ")
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
                String lowerEntry = entryName.toLowerCase(Locale.ROOT);

                if (isSuspiciousExecutableEntry(entryName, lowerEntry)) {
                    String dedupKey = fileName + "|NATIVE|" + entryName;
                    if (deduplication.add(dedupKey)) {
                        findings.add(new ScanFinding(
                                entryName,
                                ThreatCategory.NATIVE_LIBRARY_LOAD,
                                "Embedded Native / Binary Executable",
                                "Found suspicious embedded executable binary inside jar: " + entryName
                        ));
                    }
                }

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
                            String lowerNested = nestedName.toLowerCase(Locale.ROOT);
                            if (isSuspiciousExecutableEntry(nestedName, lowerNested)) {
                                String dedupKey = fileName + "|NATIVE|" + nestedName;
                                if (deduplication.add(dedupKey)) {
                                    findings.add(new ScanFinding(
                                            entryName + "!" + nestedName,
                                            ThreatCategory.NATIVE_LIBRARY_LOAD,
                                            "Embedded Native / Binary Executable",
                                            "Found suspicious embedded executable binary inside nested jar: " + nestedName
                                    ));
                                }
                            }
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

    private static boolean isSuspiciousExecutableEntry(String originalName, String lowerEntry) {
        boolean hasExecutableExt = false;
        for (String ext : EXECUTABLE_EXTENSIONS) {
            if (lowerEntry.endsWith(ext)) {
                hasExecutableExt = true;
                break;
            }
        }
        if (!hasExecutableExt) {
            return false;
        }

        // Whitelist known legitimate vendor libraries
        for (String legitimatePrefix : LEGITIMATE_NATIVE_PREFIXES) {
            if (lowerEntry.contains(legitimatePrefix.toLowerCase(Locale.ROOT))) {
                return false;
            }
        }

        // Whitelist standard system native libraries bundled in Fabric/LWJGL jars
        if (lowerEntry.contains("gpu-detect") || lowerEntry.contains("libglfw") || lowerEntry.contains("openal")) {
            return false;
        }

        return true;
    }

    private static void analyzeClassStrings(String className, List<String> strings,
                                            List<ScanFinding> findings, Set<String> deduplication) {
        String formattedClassName = className.replace('/', '.').replace(".class", "");

        for (String str : strings) {
            if (str == null || str.length() < 4) {
                continue;
            }

            // 1. Direct signature scan
            checkStringSignatures(formattedClassName, str, str, false, findings, deduplication);

            // 2. Base64 auto-decoding scan
            checkBase64Signatures(formattedClassName, str, findings, deduplication);

            // 3. Hex auto-decoding scan
            checkHexSignatures(formattedClassName, str, findings, deduplication);
        }
    }

    private static void checkStringSignatures(String className, String originalStr, String testStr,
                                              boolean isDecoded, List<ScanFinding> findings, Set<String> deduplication) {
        String lower = testStr.toLowerCase(Locale.ROOT);
        for (Signature sig : SIGNATURES) {
            if (lower.contains(sig.pattern.toLowerCase(Locale.ROOT))) {
                String dedupKey = className + "|" + sig.category + "|" + originalStr;
                if (deduplication.add(dedupKey)) {
                    String prefix = isDecoded ? "[Auto-Decoded: " + truncate(testStr, 60) + "] " : "";
                    findings.add(new ScanFinding(
                            className,
                            sig.category,
                            sig.pattern,
                            prefix + truncate(originalStr, 120)
                    ));
                }
            }
        }
    }

    private static void checkBase64Signatures(String className, String str,
                                              List<ScanFinding> findings, Set<String> deduplication) {
        Matcher matcher = BASE64_PATTERN.matcher(str);
        while (matcher.find()) {
            String candidate = matcher.group();
            String decoded = tryDecodeBase64(candidate);
            if (decoded != null && isPrintableAscii(decoded)) {
                checkStringSignatures(className, str, decoded, true, findings, deduplication);
            }
        }
    }

    private static void checkHexSignatures(String className, String str,
                                           List<ScanFinding> findings, Set<String> deduplication) {
        if (HEX_PATTERN.matcher(str).matches()) {
            String decoded = tryDecodeHex(str);
            if (decoded != null && isPrintableAscii(decoded)) {
                checkStringSignatures(className, str, decoded, true, findings, deduplication);
            }
        }
    }

    private static String tryDecodeBase64(String s) {
        try {
            byte[] bytes = Base64.getDecoder().decode(s);
            if (bytes.length > 0) {
                return new String(bytes, StandardCharsets.UTF_8);
            }
        } catch (IllegalArgumentException ignored) {}

        try {
            byte[] bytes = Base64.getUrlDecoder().decode(s);
            if (bytes.length > 0) {
                return new String(bytes, StandardCharsets.UTF_8);
            }
        } catch (IllegalArgumentException ignored) {}

        return null;
    }

    private static String tryDecodeHex(String s) {
        try {
            int len = s.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                        + Character.digit(s.charAt(i + 1), 16));
            }
            return new String(data, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isPrintableAscii(String s) {
        if (s == null || s.isEmpty()) return false;
        int printable = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 32 && c < 127) {
                printable++;
            }
        }
        return (double) printable / s.length() >= 0.85;
    }

    private static String truncate(String s, int maxLen) {
        if (s.length() <= maxLen) {
            return s;
        }
        return s.substring(0, maxLen) + "...";
    }
}
