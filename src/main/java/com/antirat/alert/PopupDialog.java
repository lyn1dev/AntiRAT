package com.antirat.alert;

import com.antirat.core.Config;
import com.antirat.scanner.ScanFinding;
import com.antirat.scanner.ScanReport;
import com.antirat.ui.AntiRatDialogApp;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.awt.GraphicsEnvironment;
import java.io.File;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Spawns the AntiRAT security UI in a dedicated, isolated OS process
 * to guarantee that the UI dialog always displays even if Minecraft crashes,
 * halts, or conflicts with other crash handlers.
 */
public final class PopupDialog {

    static {
        try {
            if (!GraphicsEnvironment.isHeadless()) {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            }
        } catch (Throwable ignored) {}
    }

    private PopupDialog() {
    }

    /**
     * Shows an interactive pop-up dialog when a mod queries the session token.
     * Spawns a dedicated standalone process so that Minecraft crashes/halts don't kill the window.
     */
    public static void showTokenAccessDecision(String modId, String fileName, Path originPath,
                                               Path configDir, String accessPoint) {
        String originStr = originPath != null ? originPath.toString() : "";
        String configStr = configDir != null ? configDir.toString() : "";

        // 1. Launch in a separate standalone process
        boolean launched = launchStandaloneProcess(
                "token_access",
                modId != null ? modId : "unknown",
                fileName != null ? fileName : "unknown.jar",
                originStr,
                configStr,
                accessPoint != null ? accessPoint : "User#getAccessToken"
        );

        // 2. Fallback to in-process Swing dialog if process spawning is disallowed
        if (!launched && !GraphicsEnvironment.isHeadless()) {
            showInProcessTokenDialog(modId, fileName, originPath, configDir, accessPoint);
        }
    }

    /**
     * Shows an interactive pop-up dialog for pre-launch detected threats.
     */
    public static void showPreLaunchThreatDecision(List<ScanReport> reports, Path configDir, Path modsDir) {
        if (reports == null || reports.isEmpty()) {
            return;
        }

        StringBuilder payload = new StringBuilder();
        for (int i = 0; i < reports.size(); i++) {
            ScanReport report = reports.get(i);
            if (i > 0) payload.append("###");
            String pathStr = report.jarPath() != null ? report.jarPath().toString() : "";
            payload.append(report.fileName()).append("||").append(pathStr).append("||");
            for (int j = 0; j < report.findings().size(); j++) {
                if (j > 0) payload.append(";;");
                ScanFinding f = report.findings().get(j);
                payload.append("[").append(f.category().name()).append("] ").append(f.sampleContent());
            }
        }

        String configStr = configDir != null ? configDir.toString() : "";
        String base64Payload = java.util.Base64.getEncoder().encodeToString(payload.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));

        boolean launched = launchStandaloneProcess(
                "prelaunch_threat_b64",
                base64Payload,
                configStr
        );

        if (!launched && !GraphicsEnvironment.isHeadless()) {
            showInProcessPreLaunchDialog(reports, configDir);
        }
    }

    /**
     * Shows a pop-up dialog when outbound token exfiltration to a webhook/C2 is blocked.
     */
    public static void showEgressBlockedAlert(String targetUrl) {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            try {
                String message = String.format(
                        "AntiRAT Security Alert: Data Exfiltration Blocked!%n%n" +
                        "An unauthorized outbound connection to a known webhook/C2 endpoint was aborted:%n" +
                        "  • Blocked URL: %s%n%n" +
                        "AntiRAT dropped the network connection to protect your session token.",
                        targetUrl
                );

                JOptionPane.showMessageDialog(
                        null,
                        message,
                        "AntiRAT - Data Exfiltration Blocked",
                        JOptionPane.WARNING_MESSAGE
                );
            } catch (Throwable ignored) {}
        });
    }

    private static boolean launchStandaloneProcess(String... processArgs) {
        try {
            String javaHome = System.getProperty("java.home");
            String javaBin = javaHome + File.separator + "bin" + File.separator + "javaw";
            if (!new File(javaBin + ".exe").exists() && !new File(javaBin).exists()) {
                javaBin = javaHome + File.separator + "bin" + File.separator + "java";
            }

            URL codeSource = PopupDialog.class.getProtectionDomain().getCodeSource().getLocation();
            String classPath = Path.of(codeSource.toURI()).toString();

            List<String> command = new ArrayList<>();
            command.add(javaBin);
            command.add("-cp");
            command.add(classPath);
            command.add("com.antirat.ui.AntiRatDialogApp");
            Collections.addAll(command, processArgs);

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.start();
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private static void showInProcessTokenDialog(String modId, String fileName, Path originPath,
                                                 Path configDir, String accessPoint) {
        SwingUtilities.invokeLater(() -> {
            try {
                String messageHtml = "<html><body style='width: 440px; font-family: sans-serif;'>"
                        + "<h2 style='color: #c0392b;'>AntiRAT: Token Access Intercepted</h2>"
                        + "<p>A mod attempted to read your private Minecraft session token:</p>"
                        + "<b>Mod ID:</b> <code>" + escapeHtml(modId) + "</code><br>"
                        + "<b>Mod File:</b> <code>" + escapeHtml(fileName) + "</code><br><br>"
                        + "<p>• <b>If you got this mod from Modrinth / CurseForge</b> (e.g. SkyBlockPv, AuthMe), press <b>Whitelist</b>.<br>"
                        + "• <b>Otherwise</b>, delete it immediately to protect your account.</p>"
                        + "</body></html>";

                Object[] options = {"Whitelist Mod", "Delete Mod File", "Keep Blocked"};
                int choice = JOptionPane.showOptionDialog(
                        null,
                        messageHtml,
                        "AntiRAT - Token Access Decision",
                        JOptionPane.YES_NO_CANCEL_OPTION,
                        JOptionPane.WARNING_MESSAGE,
                        null,
                        options,
                        options[2]
                );

                if (choice == 0 && configDir != null) {
                    Config.addWhitelist(configDir, modId);
                } else if (choice == 1 && originPath != null) {
                    Files.deleteIfExists(originPath);
                }
            } catch (Throwable ignored) {}
        });
    }

    private static void showInProcessPreLaunchDialog(List<ScanReport> reports, Path configDir) {
        try {
            JOptionPane.showMessageDialog(
                    null,
                    "AntiRAT detected malware in your mods folder:\n" + reports.get(0).fileName() + "\nLaunch halted.",
                    "AntiRAT - Malware Detected",
                    JOptionPane.ERROR_MESSAGE
            );
        } catch (Throwable ignored) {}
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
