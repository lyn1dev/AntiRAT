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

        if (!config.enabled || !config.scanner.enabled) {
            return;
        }

        Path modsDir = loader.getGameDir().resolve("mods");
        List<ScanReport> reports = JarScanner.scanModsDirectory(modsDir);

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

            alert.append(System.lineSeparator())
                 .append("================================================================================").append(System.lineSeparator());

            if (config.panicOnThreat) {
                alert.append(" [AntiRAT] Launch HALTED immediately to prevent compromise.").append(System.lineSeparator())
                     .append(" Please remove the offending mod file(s) before starting Minecraft.").append(System.lineSeparator())
                     .append("================================================================================").append(System.lineSeparator());
                System.err.println(alert);
                // Immediately halt the JVM process without running shutdown hooks
                Runtime.getRuntime().halt(1);
            } else {
                System.err.println(alert);
            }
        }
    }
}
