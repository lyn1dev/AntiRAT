package com.antirat.scanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
    void scanModsDirectoryFindsAllInfectedJars() throws Exception {
        Path modsDir = tempDir.resolve("mods");
        Files.createDirectories(modsDir);

        byte[] cleanBytes = createDummyClassWithStrings(List.of("com/good/Mod"));
        createJar(modsDir.resolve("good.jar"), "com/good/Mod.class", cleanBytes);

        byte[] evilBytes = createDummyClassWithStrings(List.of("com/bad/Mod", "api.telegram.org/bot123456:ABC-DEF"));
        createJar(modsDir.resolve("bad.jar"), "com/bad/Mod.class", evilBytes);

        List<ScanReport> reports = JarScanner.scanModsDirectory(modsDir);
        assertEquals(1, reports.size());
        assertEquals("bad.jar", reports.get(0).fileName());
        assertEquals(ThreatCategory.WEBHOOK_C2, reports.get(0).findings().get(0).category());
    }
}
