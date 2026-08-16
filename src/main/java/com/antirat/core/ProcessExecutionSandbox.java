package com.antirat.core;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Universal Behavioral Protection against unauthorized subprocess spawning and native malware droppers.
 *
 * Intercepts attempts by untrusted mods to invoke Windows/Unix command shells
 * (PowerShell, Cmd, VBScript, CSCRIPT, MSHTA, Curl, CertUtil) or execute dropped binaries.
 */
public final class ProcessExecutionSandbox {

    private static final Set<String> DANGEROUS_EXECUTABLES = Set.of(
            "powershell.exe",
            "powershell",
            "pwsh.exe",
            "pwsh",
            "cmd.exe",
            "cmd",
            "wscript.exe",
            "wscript",
            "cscript.exe",
            "cscript",
            "mshta.exe",
            "mshta",
            "certutil.exe",
            "certutil",
            "bitsadmin.exe",
            "bitsadmin",
            "curl.exe",
            "wget"
    );

    private static final Set<String> DANGEROUS_SCRIPT_EXTENSIONS = Set.of(
            ".bat",
            ".cmd",
            ".ps1",
            ".vbs",
            ".vbe",
            ".js",
            ".jse",
            ".wsf",
            ".wsh",
            ".scr",
            ".pif"
    );

    private static volatile boolean active = false;

    public static void install(Config config, ThreatHandler threatHandler) {
        if (!config.enabled || !config.processSandbox.enabled) {
            return;
        }
        active = true;
    }

    /**
     * Evaluates whether a process command line or executable name represents a suspicious shell/dropper.
     */
    public static boolean isSuspiciousProcess(List<String> command) {
        if (command == null || command.isEmpty()) {
            return false;
        }

        String exec = command.get(0).toLowerCase(Locale.ROOT).trim();
        String execBaseName = extractExecutableBaseName(exec);

        if (DANGEROUS_EXECUTABLES.contains(execBaseName)) {
            // Check if this is a legitimate browser open request (e.g. rundll32 FileProtocolHandler https://...)
            if (isSafeBrowserOpenCommand(command)) {
                return false;
            }
            return true;
        }

        for (String ext : DANGEROUS_SCRIPT_EXTENSIONS) {
            if (exec.endsWith(ext)) {
                return true;
            }
        }

        for (String arg : command) {
            String lowerArg = arg.toLowerCase(Locale.ROOT);
            for (String ext : DANGEROUS_SCRIPT_EXTENSIONS) {
                if (lowerArg.endsWith(ext) || lowerArg.contains(ext + " ")) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Extracts filename from full executable path.
     */
    private static String extractExecutableBaseName(String fullPath) {
        int idx = Math.max(fullPath.lastIndexOf('/'), fullPath.lastIndexOf('\\'));
        if (idx != -1 && idx + 1 < fullPath.length()) {
            return fullPath.substring(idx + 1);
        }
        return fullPath;
    }

    /**
     * Whitelists legitimate browser link actions (e.g. clicking Modrinth/Discord/Wiki URLs in-game).
     */
    private static boolean isSafeBrowserOpenCommand(List<String> command) {
        if (command.size() < 2) {
            return false;
        }
        String fullCmd = String.join(" ", command).toLowerCase(Locale.ROOT);
        return fullCmd.contains("fileprotocolhandler http") || fullCmd.contains("xdg-open http");
    }

    public static boolean isActive() {
        return active;
    }
}
