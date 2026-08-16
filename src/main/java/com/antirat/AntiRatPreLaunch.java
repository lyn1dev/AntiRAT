package com.antirat;

import com.antirat.core.Config;
import com.antirat.core.RatLogger;
import com.antirat.scanner.JarScanner;
import com.antirat.scanner.ScanFinding;
import com.antirat.scanner.ScanReport;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.entrypoint.PreLaunchEntrypoint;

import java.nio.file.Path;
import java.util.List;

/**
 * PreLaunch entrypoint for AntiRAT.
 *
 * Runs early static analysis across all mod jars in the mods directory before
 * mod initializers or game classes are loaded into memory.
 */
public final class AntiRatPreLaunch implements PreLaunchEntrypoint {

    @Override
    public void onPreLaunch() {
        FabricLoader loader = FabricLoader.getInstance();
        Config config = Config.load(loader.getConfigDir());
        RatLogger logger = new RatLogger(loader.getGameDir());

        if (config.debug) {
            logger.log("AntiRAT preLaunch initialized, loader version " + loader.getRawGameVersion());
        }

        // Initialize ThreatHandler early so mixins are protected from start
        AntiRatMod.initEarly();

        // Install JVM-wide network egress filter
        com.antirat.network.NetworkEgressFilter.install(config, AntiRatMod.getThreatHandler());

        if (!config.enabled || !config.scanner.enabled) {
            return;
        }

        java.util.Set<Path> allJarPaths = new java.util.HashSet<>();
        Path modsDir = loader.getGameDir().resolve("mods").toAbsolutePath().normalize();
        if (java.nio.file.Files.isDirectory(modsDir)) {
            try (java.nio.file.DirectoryStream<Path> s = java.nio.file.Files.newDirectoryStream(modsDir, "*.jar")) {
                for (Path p : s) {
                    if (java.nio.file.Files.isRegularFile(p)) {
                        allJarPaths.add(p.toAbsolutePath().normalize());
                    }
                }
            } catch (Exception ignored) {}
        }
        Path altModsDir = Path.of("mods").toAbsolutePath().normalize();
        if (java.nio.file.Files.isDirectory(altModsDir) && !altModsDir.equals(modsDir)) {
            try (java.nio.file.DirectoryStream<Path> s = java.nio.file.Files.newDirectoryStream(altModsDir, "*.jar")) {
                for (Path p : s) {
                    if (java.nio.file.Files.isRegularFile(p)) {
                        allJarPaths.add(p.toAbsolutePath().normalize());
                    }
                }
            } catch (Exception ignored) {}
        }

        List<ScanReport> reports = allJarPaths.parallelStream()
                .filter(p -> {
                    String fileName = p.getFileName().toString();
                    String baseName = fileName.endsWith(".jar") ? fileName.substring(0, fileName.length() - 4) : fileName;
                    return !config.isWhitelisted(fileName) && !config.isWhitelisted(baseName);
                })
                .map(JarScanner::scanJar)
                .filter(ScanReport::hasThreats)
                .toList();

        if (!reports.isEmpty()) {
            StringBuilder alert = new StringBuilder();
            alert.append(System.lineSeparator())
                 .append("================================================================================").append(System.lineSeparator())
                 .append(" [AntiRAT] [CRITICAL SECURITY ALERT] MALICIOUS MOD(S) DETECTED IN MODS FOLDER!   ").append(System.lineSeparator())
                 .append("================================================================================").append(System.lineSeparator())
                 .append("Pre-launch static scanning identified known malware/stealer signatures:").append(System.lineSeparator());

            for (ScanReport report : reports) {
                alert.append(System.lineSeparator())
                     .append(" > Mod File: ").append(report.fileName()).append(System.lineSeparator());
                for (ScanFinding finding : report.findings()) {
                    alert.append("   - ").append(finding.toString()).append(System.lineSeparator());
                    if (config.log.enabled) {
                        logger.log("SCANNER_DETECTION file=" + report.fileName() + " " + finding);
                    }
                }
            }

            alert.append(" [AntiRAT] Launch HALTED immediately to prevent compromise.").append(System.lineSeparator())
                 .append(" Please remove the offending mod file(s) before starting Minecraft.").append(System.lineSeparator())
                 .append("================================================================================").append(System.lineSeparator());
            System.err.println(alert);

            // Display interactive native dialog with Whitelist & Delete options
            com.antirat.alert.PopupDialog.showPreLaunchThreatDecision(reports, loader.getConfigDir(), modsDir);

            // Immediately halt the JVM process without running shutdown hooks
            Runtime.getRuntime().halt(1);
        }
    }
}
