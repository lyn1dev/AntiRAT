package com.antirat.scanner;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class JarScannerVerification {

    public static void main(String[] args) throws Exception {
        System.out.println("[JarScannerVerification] Running Rank 1 Base64/Hex Auto-Decoding & Entropy tests...");
        Path tempDir = Files.createTempDirectory("antirat-scanner-test");

        try {
            testCleanMod(tempDir);
            testWebhookAndStealerDetection(tempDir);
            testBase64AutoDecoding(tempDir);
            testHexAutoDecoding(tempDir);
            testNestedJarDetection(tempDir);
            testDirectoryScan(tempDir);
            System.out.println("[JarScannerVerification] ALL SCANNER & DEOBFUSCATION TESTS PASSED! (6/6)");
        } finally {
            deleteRecursive(tempDir);
        }
    }

    private static void testCleanMod(Path tempDir) throws Exception {
        Path cleanJar = tempDir.resolve("clean-mod.jar");
        byte[] cleanClass = createDummyClass(List.of("com/example/CleanMod", "java/lang/Object", "<init>", "()V"));
        createJar(cleanJar, "com/example/CleanMod.class", cleanClass);

        ScanReport report = JarScanner.scanJar(cleanJar);
        if (report.hasThreats() || !report.findings().isEmpty()) {
            throw new AssertionError("Clean mod falsely flagged: " + report.findings());
        }
        System.out.println("  ✓ Clean mod passed without false positives");
    }

    private static void testWebhookAndStealerDetection(Path tempDir) throws Exception {
        Path evilJar = tempDir.resolve("evil-rat.jar");
        byte[] evilClass = createDummyClass(List.of(
                "com/evil/Stealer",
                "https://discord.com/api/webhooks/1234567890/token-here",
                "C:/Users/victim/AppData/Roaming/.minecraft/launcher_accounts.json",
                "java/lang/ProcessBuilder"
        ));
        createJar(evilJar, "com/evil/Stealer.class", evilClass);

        ScanReport report = JarScanner.scanJar(evilJar);
        if (!report.hasThreats() || report.findings().size() != 3) {
            throw new AssertionError("Expected 3 threats, got: " + report.findings());
        }

        List<ThreatCategory> categories = report.findings().stream().map(ScanFinding::category).toList();
        if (!categories.contains(ThreatCategory.WEBHOOK_C2) ||
            !categories.contains(ThreatCategory.STEALER_TARGET) ||
            !categories.contains(ThreatCategory.PROCESS_EXECUTION)) {
            throw new AssertionError("Missing expected threat categories: " + categories);
        }
        System.out.println("  ✓ Direct webhook, stealer target, and ProcessBuilder detected");
    }

    private static void testBase64AutoDecoding(Path tempDir) throws Exception {
        Path b64Jar = tempDir.resolve("b64-rat.jar");
        String plainWebhook = "https://discord.com/api/webhooks/999/secrettoken";
        String b64Webhook = Base64.getEncoder().encodeToString(plainWebhook.getBytes(StandardCharsets.UTF_8));

        byte[] b64Class = createDummyClass(List.of("com/b64/Mod", b64Webhook));
        createJar(b64Jar, "com/b64/Mod.class", b64Class);

        ScanReport report = JarScanner.scanJar(b64Jar);
        if (!report.hasThreats() || report.findings().isEmpty()) {
            throw new AssertionError("Failed to detect Base64-obfuscated webhook");
        }
        ScanFinding finding = report.findings().get(0);
        if (finding.category() != ThreatCategory.WEBHOOK_C2 || !finding.sampleContent().contains("[Auto-Decoded:")) {
            throw new AssertionError("Base64 auto-decoding finding invalid: " + finding);
        }
        System.out.println("  ✓ Base64-encoded Discord webhook automatically decoded and intercepted");
    }

    private static void testHexAutoDecoding(Path tempDir) throws Exception {
        Path hexJar = tempDir.resolve("hex-rat.jar");
        String plainStealer = "launcher_accounts.json";
        StringBuilder hex = new StringBuilder();
        for (byte b : plainStealer.getBytes(StandardCharsets.UTF_8)) {
            hex.append(String.format("%02x", b));
        }

        byte[] hexClass = createDummyClass(List.of("com/hex/Mod", hex.toString()));
        createJar(hexJar, "com/hex/Mod.class", hexClass);

        ScanReport report = JarScanner.scanJar(hexJar);
        if (!report.hasThreats() || report.findings().isEmpty() || report.findings().get(0).category() != ThreatCategory.STEALER_TARGET) {
            throw new AssertionError("Failed to detect Hex-obfuscated stealer target: " + report.findings());
        }
        System.out.println("  ✓ Hex-encoded stealer target string automatically decoded and intercepted");
    }

    private static void testNestedJarDetection(Path tempDir) throws Exception {
        Path outerJar = tempDir.resolve("outer-container.jar");

        byte[] innerClassBytes = createDummyClass(List.of(
                "com/nested/Dropper",
                "https://discordapp.com/api/webhooks/999/secret",
                "powershell -ExecutionPolicy Bypass -Command IEX"
        ));

        ByteArrayOutputStream nestedBaos = new ByteArrayOutputStream();
        try (ZipOutputStream nestedZos = new ZipOutputStream(nestedBaos)) {
            nestedZos.putNextEntry(new ZipEntry("com/nested/Dropper.class"));
            nestedZos.write(innerClassBytes);
            nestedZos.closeEntry();
        }

        try (ZipOutputStream outerZos = new ZipOutputStream(Files.newOutputStream(outerJar))) {
            outerZos.putNextEntry(new ZipEntry("META-INF/jars/nested-payload.jar"));
            outerZos.write(nestedBaos.toByteArray());
            outerZos.closeEntry();
        }

        ScanReport report = JarScanner.scanJar(outerJar);
        if (!report.hasThreats() || report.findings().size() < 2) {
            throw new AssertionError("Failed to detect nested jar payload: " + report.findings());
        }
        System.out.println("  ✓ Nested jar embedded payloads detected");
    }

    private static void testDirectoryScan(Path tempDir) throws Exception {
        Path modsDir = tempDir.resolve("mods");
        Files.createDirectories(modsDir);

        createJar(modsDir.resolve("good.jar"), "com/good/Mod.class", createDummyClass(List.of("com/good/Mod")));
        createJar(modsDir.resolve("bad.jar"), "com/bad/Mod.class", createDummyClass(List.of("com/bad/Mod", "api.telegram.org/bot123456:ABC-DEF")));

        List<ScanReport> reports = JarScanner.scanModsDirectory(modsDir);
        if (reports.size() != 1 || !reports.get(0).fileName().equals("bad.jar")) {
            throw new AssertionError("Directory scan failed: " + reports);
        }
        System.out.println("  ✓ Directory scan accurately isolated only infected jar");
    }

    private static byte[] createDummyClass(List<String> utf8Strings) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        dos.writeInt(0xCAFEBABE);
        dos.writeShort(0);
        dos.writeShort(61);
        dos.writeShort(utf8Strings.size() + 1);

        for (String s : utf8Strings) {
            dos.writeByte(1);
            dos.writeUTF(s);
        }

        dos.writeShort(0x0001);
        dos.writeShort(1);
        dos.writeShort(0);
        dos.writeShort(0);
        dos.writeShort(0);
        dos.writeShort(0);
        dos.writeShort(0);

        dos.flush();
        return baos.toByteArray();
    }

    private static void createJar(Path jarPath, String classEntryName, byte[] classBytes) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jarPath))) {
            zos.putNextEntry(new ZipEntry(classEntryName));
            zos.write(classBytes);
            zos.closeEntry();
        }
    }

    private static void deleteRecursive(Path path) {
        try {
            if (Files.isDirectory(path)) {
                try (var s = Files.list(path)) {
                    s.forEach(JarScannerVerification::deleteRecursive);
                }
            }
            Files.deleteIfExists(path);
        } catch (Exception ignored) {}
    }
}
