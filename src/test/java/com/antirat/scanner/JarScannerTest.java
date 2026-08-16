package com.antirat.scanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JarScannerTest {

    @TempDir
    Path tempDir;

    private static byte[] createDummyClassWithStrings(List<String> utf8Strings) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        dos.writeInt(0xCAFEBABE); // magic
        dos.writeShort(0);        // minor
        dos.writeShort(61);       // major (Java 17)

        int cpCount = utf8Strings.size() + 1;
        dos.writeShort(cpCount);

        for (String s : utf8Strings) {
            dos.writeByte(1);     // CONSTANT_Utf8 tag
            dos.writeUTF(s);
        }

        dos.writeShort(0x0001);   // access_flags (ACC_PUBLIC)
        dos.writeShort(1);        // this_class index
        dos.writeShort(0);        // super_class
        dos.writeShort(0);        // interfaces_count
        dos.writeShort(0);        // fields_count
        dos.writeShort(0);        // methods_count
        dos.writeShort(0);        // attributes_count

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

    @Test
    void cleanModJarReportsNoThreats() throws Exception {
        Path cleanJar = tempDir.resolve("clean-mod.jar");
        byte[] cleanClass = createDummyClassWithStrings(List.of("com/example/CleanMod", "java/lang/Object", "<init>", "()V"));
        createJar(cleanJar, "com/example/CleanMod.class", cleanClass);

        ScanReport report = JarScanner.scanJar(cleanJar);
        assertFalse(report.hasThreats());
        assertTrue(report.findings().isEmpty());
    }

    @Test
    void detectsDiscordWebhookAndStealerTarget() throws Exception {
        Path evilJar = tempDir.resolve("evil-rat.jar");
        byte[] evilClass = createDummyClassWithStrings(List.of(
                "com/evil/Stealer",
                "https://discord.com/api/webhooks/1234567890/token-here",
                "C:/Users/victim/AppData/Roaming/.minecraft/launcher_accounts.json",
                "java/lang/ProcessBuilder"
        ));
        createJar(evilJar, "com/evil/Stealer.class", evilClass);

        ScanReport report = JarScanner.scanJar(evilJar);
        assertTrue(report.hasThreats());
        assertEquals(3, report.findings().size());

        List<ThreatCategory> categories = report.findings().stream().map(ScanFinding::category).toList();
        assertTrue(categories.contains(ThreatCategory.WEBHOOK_C2));
        assertTrue(categories.contains(ThreatCategory.STEALER_TARGET));
        assertTrue(categories.contains(ThreatCategory.PROCESS_EXECUTION));
    }

    @Test
    void autoDecodesBase64ObfuscatedWebhook() throws Exception {
        Path b64Jar = tempDir.resolve("obfuscated-rat.jar");
        String plainWebhook = "https://discord.com/api/webhooks/987654321/supersecrettoken";
        String base64Webhook = Base64.getEncoder().encodeToString(plainWebhook.getBytes(StandardCharsets.UTF_8));

        byte[] b64Class = createDummyClassWithStrings(List.of(
                "com/obf/Loader",
                base64Webhook
        ));
        createJar(b64Jar, "com/obf/Loader.class", b64Class);

        ScanReport report = JarScanner.scanJar(b64Jar);
        assertTrue(report.hasThreats());
        assertTrue(report.findings().stream().anyMatch(f ->
                f.category() == ThreatCategory.WEBHOOK_C2 && f.sampleContent().contains("[Auto-Decoded:")
        ));
    }

    @Test
    void autoDecodesHexObfuscatedStealerPath() throws Exception {
        Path hexJar = tempDir.resolve("hex-rat.jar");
        String plainStealer = "launcher_accounts.json";
        StringBuilder hex = new StringBuilder();
        for (byte b : plainStealer.getBytes(StandardCharsets.UTF_8)) {
            hex.append(String.format("%02x", b));
        }

        byte[] hexClass = createDummyClassWithStrings(List.of(
                "com/obf/HexLoader",
                hex.toString()
        ));
        createJar(hexJar, "com/obf/HexLoader.class", hexClass);

        ScanReport report = JarScanner.scanJar(hexJar);
        assertTrue(report.hasThreats());
        assertTrue(report.findings().stream().anyMatch(f -> f.category() == ThreatCategory.STEALER_TARGET));
    }

    @Test
    void detectsThreatsInNestedJars() throws Exception {
        Path outerJar = tempDir.resolve("outer-container.jar");

        byte[] innerClassBytes = createDummyClassWithStrings(List.of(
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
        assertTrue(report.hasThreats());
        List<ThreatCategory> categories = report.findings().stream().map(ScanFinding::category).toList();
        assertTrue(categories.contains(ThreatCategory.WEBHOOK_C2));
        assertTrue(categories.contains(ThreatCategory.PROCESS_EXECUTION));
    }

    @Test
    void detectsEmbeddedDllBinary() throws Exception {
        Path dllJar = tempDir.resolve("native-dropper.jar");
        byte[] dummyClass = createDummyClassWithStrings(List.of("com/dropper/Main"));

        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(dllJar))) {
            zos.putNextEntry(new ZipEntry("com/dropper/Main.class"));
            zos.write(dummyClass);
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("assets/payload.dll"));
            zos.write(new byte[]{0x4D, 0x5A, 0x00, 0x00}); // MZ header
            zos.closeEntry();
        }

        ScanReport report = JarScanner.scanJar(dllJar);
        assertTrue(report.hasThreats());
        List<ThreatCategory> categories = report.findings().stream().map(ScanFinding::category).toList();
        assertTrue(categories.contains(ThreatCategory.NATIVE_LIBRARY_LOAD));
    }

    @Test
    void detectsSystemLoadLibraryCall() throws Exception {
        Path loadJar = tempDir.resolve("system-load.jar");
        byte[] loadClass = createDummyClassWithStrings(List.of("com/loader/NativeMod", "java/lang/System.loadLibrary"));
        createJar(loadJar, "com/loader/NativeMod.class", loadClass);

        ScanReport report = JarScanner.scanJar(loadJar);
        assertTrue(report.hasThreats());
        assertEquals(ThreatCategory.NATIVE_LIBRARY_LOAD, report.findings().get(0).category());
    }
}
