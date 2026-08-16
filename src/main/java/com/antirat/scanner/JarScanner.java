package com.antirat.scanner;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
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
            ".dll", ".exe", ".so", ".dylib", ".vbs", ".bat", ".cmd", ".ps1", ".scr", ".pif", ".tmp", ".bin"
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
            new Signature(ThreatCategory.WEBHOOK_C2, "45.61.176.132"),
            new Signature(ThreatCategory.WEBHOOK_C2, ":8787/login"),
            new Signature(ThreatCategory.WEBHOOK_C2, "sylphie"),
            new Signature(ThreatCategory.WEBHOOK_C2, "nebulaloader"),
            new Signature(ThreatCategory.WEBHOOK_C2, "sbft.cc"),
            new Signature(ThreatCategory.WEBHOOK_C2, "r3m3mb3r"),
            new Signature(ThreatCategory.WEBHOOK_C2, "ultimatelogger"),
            new Signature(ThreatCategory.WEBHOOK_C2, "radioegor146"),
            new Signature(ThreatCategory.WEBHOOK_C2, "onrender.com"),
            new Signature(ThreatCategory.WEBHOOK_C2, "herokuapp.com"),
            new Signature(ThreatCategory.WEBHOOK_C2, "pastebin.com/raw/"),
            new Signature(ThreatCategory.WEBHOOK_C2, "hastebin.com/raw/"),
            new Signature(ThreatCategory.WEBHOOK_C2, "transfer.sh"),
            new Signature(ThreatCategory.WEBHOOK_C2, "gofile.io"),
            new Signature(ThreatCategory.WEBHOOK_C2, "ngrok-free.app"),
            new Signature(ThreatCategory.WEBHOOK_C2, "intfive"),
            new Signature(ThreatCategory.WEBHOOK_C2, "jooon.xyz"),
            new Signature(ThreatCategory.WEBHOOK_C2, "taunahi"),

            // Stealer Targets
            new Signature(ThreatCategory.STEALER_TARGET, "launcher_accounts.json"),
            new Signature(ThreatCategory.STEALER_TARGET, "launcher_profiles.json"),
            new Signature(ThreatCategory.STEALER_TARGET, "microsoft_accounts.json"),
            new Signature(ThreatCategory.STEALER_TARGET, ".minecraft/launcher_accounts"),
            new Signature(ThreatCategory.STEALER_TARGET, "Roaming/.minecraft"),
            new Signature(ThreatCategory.STEALER_TARGET, "Local/Google/Chrome"),
            new Signature(ThreatCategory.STEALER_TARGET, "AppData/Local/BraveSoftware"),
            new Signature(ThreatCategory.STEALER_TARGET, "PrismLauncher/accounts"),
            new Signature(ThreatCategory.STEALER_TARGET, "MultiMC/accounts"),
            new Signature(ThreatCategory.STEALER_TARGET, "com.modrinth.theseus/settings"),
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
        List<Path> jarFiles = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(modsDir, "*.jar")) {
            for (Path jarPath : stream) {
                if (Files.isRegularFile(jarPath)) {
                    jarFiles.add(jarPath);
                }
            }
        } catch (IOException e) {
            return Collections.emptyList();
        }

        return jarFiles.parallelStream()
                .map(JarScanner::scanJar)
                .filter(ScanReport::hasThreats)
                .toList();
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
                    try {
                        byte[] classBytes = zis.readAllBytes();
                        List<String> strings = ClassConstantPoolReader.extractUtf8Strings(new ByteArrayInputStream(classBytes));
                        List<String> immediateStrings = extractBytecodeImmediateStrings(classBytes);
                        if (!immediateStrings.isEmpty()) {
                            strings.addAll(immediateStrings);
                        }
                        analyzeClassStrings(entryName, strings, findings, deduplication);
                    } catch (Exception ignored) {}
                } else if (entryName.equalsIgnoreCase("fabric.mod.json") || entryName.equalsIgnoreCase("mcmod.info")) {
                    try {
                        byte[] bytes = zis.readAllBytes();
                        String jsonText = new String(bytes, StandardCharsets.UTF_8);
                        analyzeModJson(fileName + "!" + entryName, jsonText, findings, deduplication);
                    } catch (Exception ignored) {}
                } else if (!entryName.contains("/") && (entryName.endsWith(".json") || entryName.endsWith(".cfg") || entryName.endsWith(".properties"))) {
                    // Only scan root config files (e.g. config.json in TsmClient), ignore deep assets/models/textures
                    try {
                        byte[] bytes = zis.readAllBytes();
                        if (bytes.length < 65536) { // Max 64KB for root configs
                            String text = new String(bytes, StandardCharsets.UTF_8);
                            analyzeResourceText(fileName + "!" + entryName, text, findings, deduplication);
                        }
                    } catch (Exception ignored) {}
                } else if (!entryName.contains("/") && entryName.length() >= 16 && HEX_PATTERN.matcher(entryName).matches()) {
                    // Suspicious root hex-named resource (e.g. Polar / Taunahi encrypted RC4 payload)
                    try {
                        byte[] rawBytes = zis.readAllBytes();
                        if (rawBytes.length > 512) {
                            byte[] decrypted = tryRc4DecryptWithHexKey(rawBytes, entryName);
                            if (decrypted != null && isJavaClassOrJar(decrypted)) {
                                String dedupKey = fileName + "|ENCRYPTED_PAYLOAD|" + entryName;
                                if (deduplication.add(dedupKey)) {
                                    findings.add(new ScanFinding(
                                            entryName,
                                            ThreatCategory.PROCESS_EXECUTION,
                                            "Encrypted Bytecode Payload Dropper",
                                            "Found hidden encrypted class/jar payload (" + rawBytes.length + " bytes) decrypted via RC4 with entry key: " + entryName
                                    ));
                                }
                                try {
                                    List<String> innerStrings = ClassConstantPoolReader.extractUtf8Strings(new ByteArrayInputStream(decrypted));
                                    analyzeClassStrings(entryName + "!DecryptedPayload", innerStrings, findings, deduplication);
                                } catch (Exception ignored) {}
                            }
                        }
                    } catch (Exception ignored) {}
                } else if (entryName.endsWith(".jar") || entryName.endsWith(".zip")) {
                    // Nested jar scan (only inspect embedded class files and natives)
                    try {
                        byte[] nestedJarBytes = zis.readAllBytes();
                        try (ZipInputStream nestedZis = new ZipInputStream(new ByteArrayInputStream(nestedJarBytes))) {
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
                                    byte[] nestedClassBytes = nestedZis.readAllBytes();
                                    List<String> nestedStrings = ClassConstantPoolReader.extractUtf8Strings(new ByteArrayInputStream(nestedClassBytes));
                                    analyzeClassStrings(entryName + "!" + nestedName, nestedStrings, findings, deduplication);
                                }
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

    private static void analyzeModJson(String location, String jsonText,
                                       List<ScanFinding> findings, Set<String> deduplication) {
        String lower = jsonText.toLowerCase(Locale.ROOT);
        for (Signature sig : SIGNATURES) {
            if (lower.contains(sig.pattern.toLowerCase(Locale.ROOT))) {
                String dedupKey = location + "|" + sig.category + "|" + sig.pattern;
                if (deduplication.add(dedupKey)) {
                    findings.add(new ScanFinding(
                            location,
                            sig.category,
                            "Mod Metadata Signature: " + sig.pattern,
                            "Mod descriptor contained malware signature: " + sig.pattern
                    ));
                }
            }
        }
    }

    private static void analyzeResourceText(String location, String text,
                                            List<ScanFinding> findings, Set<String> deduplication) {
        checkStringSignatures(location, text, text, false, findings, deduplication);
        checkBase64Signatures(location, text, findings, deduplication);
        checkHexSignatures(location, text, findings, deduplication);
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

        Set<String> matchedDirectSignatures = new HashSet<>();
        StringBuilder strippedConcat = new StringBuilder();

        for (String str : strings) {
            if (str == null || str.length() < 2) {
                continue;
            }

            // Accumulate de-noised constant pool strings
            String stripped = str.replaceAll("[*@\\s\u00A0\uFFFD\u200B\u200C\u200D]+", "").toLowerCase(Locale.ROOT);
            if (stripped.length() >= 2) {
                strippedConcat.append(stripped);
            }

            // Check alternating-junk obfuscated strings (e.g. Jooon / IntFive stealer patterns)
            String lowerStr = str.toLowerCase(Locale.ROOT);
            if (!lowerStr.contains("launcher_accounts.json") && !lowerStr.contains("microsoft_accounts.json")) {
                String alphaOnly = str.replaceAll("[^a-zA-Z]+", "").toLowerCase(Locale.ROOT);
                if (alphaOnly.length() >= 6) {
                    if (alphaOnly.contains("microsoftaccounts") || alphaOnly.contains("launcheraccounts")
                            || alphaOnly.contains("intfive") || alphaOnly.contains("sbftcc") || alphaOnly.contains("r3m3mb3r")
                            || alphaOnly.contains("ultimatelogger") || alphaOnly.contains("radioegor")) {
                        String dedupKey = formattedClassName + "|ALPHA|" + alphaOnly;
                        if (deduplication.add(dedupKey)) {
                            ThreatCategory cat = (alphaOnly.contains("accounts")) ? ThreatCategory.STEALER_TARGET : ThreatCategory.WEBHOOK_C2;
                            findings.add(new ScanFinding(
                                    formattedClassName,
                                    cat,
                                    "Deobfuscated Stealer Target: " + alphaOnly,
                                    "Deobfuscated alternating-junk string: " + truncate(str, 100)
                            ));
                        }
                    }
                }
            }

            // 1. Direct signature scan
            checkStringSignaturesWithTracking(formattedClassName, str, str, false, findings, deduplication, matchedDirectSignatures);

            // 2. Base64 auto-decoding scan
            checkBase64Signatures(formattedClassName, str, findings, deduplication);

            // 3. Hex auto-decoding scan
            checkHexSignatures(formattedClassName, str, findings, deduplication);
        }

        // 4. Fragmented / Junk-padded constant pool signature scan (for high-confidence stealer signatures)
        String combined = strippedConcat.toString();
        for (Signature sig : SIGNATURES) {
            if (matchedDirectSignatures.contains(sig.pattern)) {
                continue;
            }
            if (sig.pattern.equals("sbft.cc") || sig.pattern.equals("r3m3mb3r") || sig.pattern.equals("ultimatelogger")
                    || sig.pattern.equals("radioegor146") || sig.pattern.contains("webhook") || sig.pattern.contains("launcher_accounts")
                    || sig.pattern.contains("microsoft_accounts") || sig.pattern.contains("intfive") || sig.pattern.contains("jooon")) {
                String sigPatternStripped = sig.pattern.replaceAll("[*@\\s\\./:]+", "").toLowerCase(Locale.ROOT);
                if (sigPatternStripped.length() >= 5 && combined.contains(sigPatternStripped)) {
                    String dedupKey = formattedClassName + "|" + sig.category + "|" + sig.pattern;
                    if (deduplication.add(dedupKey)) {
                        findings.add(new ScanFinding(
                                formattedClassName,
                                sig.category,
                                "Deobfuscated Fragmented Constant: " + sig.pattern,
                                "Constant pool contained fragmented/junk-padded malware signature: " + sig.pattern
                        ));
                    }
                }
            }
        }
    }

    private static void checkStringSignaturesWithTracking(String className, String originalStr, String testStr,
                                                          boolean isDecoded, List<ScanFinding> findings,
                                                          Set<String> deduplication, Set<String> matchedSignatures) {
        String lower = testStr.toLowerCase(Locale.ROOT);
        for (Signature sig : SIGNATURES) {
            if (lower.contains(sig.pattern.toLowerCase(Locale.ROOT))) {
                matchedSignatures.add(sig.pattern);
                String dedupKey = className + "|" + sig.category + "|" + originalStr;
                if (deduplication.add(dedupKey)) {
                    String prefix = isDecoded ? "[Auto-Decoded: " + truncate(testStr, 60) + "] " : "";
                    findings.add(new ScanFinding(
                            className,
                            sig.category,
                            prefix + sig.pattern,
                            "Detected signature: " + sig.pattern + " in " + truncate(originalStr, 80)
                    ));
                }
            }
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
            if (candidate.length() > 512) {
                continue; // Skip excessively large base64 blobs (e.g. embedded pictures/textures)
            }
            byte[] raw = tryDecodeBase64Bytes(candidate);
            if (raw != null && raw.length >= 8) {
                // 1. Direct Base64 plain text
                String decoded = new String(raw, StandardCharsets.UTF_8);
                if (isPrintableAscii(decoded)) {
                    checkStringSignatures(className, str, decoded, true, findings, deduplication);
                }

                // 2. Ultra-Fast Base64 + Single-Byte XOR key sweep (0x01..0xFF)
                for (int key = 1; key <= 255; key++) {
                    if (hasQuickXorKeyword(raw, key)) {
                        byte[] xorBytes = new byte[raw.length];
                        for (int i = 0; i < raw.length; i++) {
                            xorBytes[i] = (byte) (raw[i] ^ key);
                        }
                        String xorDecoded = new String(xorBytes, StandardCharsets.UTF_8);
                        if (isPrintableAscii(xorDecoded)) {
                            checkStringSignatures(className, str, xorDecoded, true, findings, deduplication);
                        }
                    }
                }
            }
        }
    }

    private static boolean hasQuickXorKeyword(byte[] bytes, int key) {
        // Fast byte search for "http", "disc", "laun", "acco", "r3m3", "sbft"
        byte h = (byte) ('h' ^ key), t = (byte) ('t' ^ key), p = (byte) ('p' ^ key);
        byte d = (byte) ('d' ^ key), i = (byte) ('i' ^ key), s = (byte) ('s' ^ key), c = (byte) ('c' ^ key);
        byte l = (byte) ('l' ^ key), a = (byte) ('a' ^ key), u = (byte) ('u' ^ key), n = (byte) ('n' ^ key);
        byte o = (byte) ('o' ^ key);

        for (int idx = 0; idx < bytes.length - 3; idx++) {
            byte b0 = bytes[idx];
            byte b1 = bytes[idx + 1];
            byte b2 = bytes[idx + 2];
            byte b3 = bytes[idx + 3];

            if ((b0 == h && b1 == t && b2 == t && b3 == p) || // http
                (b0 == d && b1 == i && b2 == s && b3 == c) || // disc
                (b0 == l && b1 == a && b2 == u && b3 == n) || // laun
                (b0 == a && b1 == c && b2 == c && b3 == o)) {  // acco
                return true;
            }
        }
        return false;
    }

    private static void checkHexSignatures(String className, String str,
                                           List<ScanFinding> findings, Set<String> deduplication) {
        if (str.length() >= 16 && str.length() <= 256 && HEX_PATTERN.matcher(str).matches()) {
            String decoded = tryDecodeHex(str);
            if (decoded != null && isPrintableAscii(decoded)) {
                checkStringSignatures(className, str, decoded, true, findings, deduplication);
            }
        }
    }

    private static byte[] tryDecodeBase64Bytes(String s) {
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException ignored) {}

        try {
            return Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException ignored) {}

        return null;
    }

    private static String tryDecodeBase64(String s) {
        byte[] bytes = tryDecodeBase64Bytes(s);
        return (bytes != null && bytes.length > 0) ? new String(bytes, StandardCharsets.UTF_8) : null;
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

    private static List<String> extractBytecodeImmediateStrings(byte[] classBytes) {
        List<String> result = new ArrayList<>();
        List<Integer> currentSeq = new ArrayList<>();

        for (int i = 0; i < classBytes.length; i++) {
            int b = classBytes[i] & 0xFF;
            if (b == 0x10 && i + 1 < classBytes.length) { // BIPUSH opcode
                int val = classBytes[i + 1] & 0xFF;
                if (val >= 32 && val <= 126) {
                    currentSeq.add(val);
                } else {
                    flushImmediateSeq(currentSeq, result);
                }
                i++;
            } else if (b == 0x11 && i + 2 < classBytes.length) { // SIPUSH opcode
                int val = ((classBytes[i + 1] & 0xFF) << 8) | (classBytes[i + 2] & 0xFF);
                if (val >= 32 && val <= 126) {
                    currentSeq.add(val);
                } else {
                    flushImmediateSeq(currentSeq, result);
                }
                i += 2;
            }
        }
        flushImmediateSeq(currentSeq, result);
        return result;
    }

    private static void flushImmediateSeq(List<Integer> seq, List<String> result) {
        if (seq.size() >= 5) {
            StringBuilder sb = new StringBuilder();
            for (int val : seq) {
                sb.append((char) val);
            }
            result.add(sb.toString());
        }
        seq.clear();
    }

    private static byte[] tryRc4DecryptWithHexKey(byte[] payload, String hexKey) {
        try {
            int len = hexKey.length();
            byte[] key = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                key[i / 2] = (byte) ((Character.digit(hexKey.charAt(i), 16) << 4)
                        + Character.digit(hexKey.charAt(i + 1), 16));
            }

            int[] s = new int[256];
            for (int i = 0; i < 256; i++) s[i] = i;
            int j = 0;
            for (int i = 0; i < 256; i++) {
                j = (j + s[i] + (key[i % key.length] & 0xFF)) % 256;
                int temp = s[i]; s[i] = s[j]; s[j] = temp;
            }

            byte[] decrypted = new byte[payload.length];
            int i = 0; j = 0;
            for (int k = 0; k < payload.length; k++) {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                int temp = s[i]; s[i] = s[j]; s[j] = temp;
                int t = (s[i] + s[j]) % 256;
                decrypted[k] = (byte) (payload[k] ^ s[t]);
            }
            return decrypted;
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isJavaClassOrJar(byte[] bytes) {
        if (bytes == null || bytes.length < 4) return false;
        // 0xCAFEBABE (Class file) or PK\x03\x04 (Zip / Jar file)
        return ((bytes[0] & 0xFF) == 0xCA && (bytes[1] & 0xFF) == 0xFE && (bytes[2] & 0xFF) == 0xBA && (bytes[3] & 0xFF) == 0xBE)
                || ((bytes[0] & 0xFF) == 0x50 && (bytes[1] & 0xFF) == 0x4B && (bytes[2] & 0xFF) == 0x03 && (bytes[3] & 0xFF) == 0x04);
    }
}
