package com.antirat.core;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Universal Behavioral Protection against filesystem credential and token theft.
 *
 * Intercepts and monitors unauthorized attempts by untrusted mods to traverse
 * or read launcher credential files on disk across all major Minecraft launchers:
 * - Official Minecraft Launcher (launcher_accounts.json, launcher_profiles.json)
 * - Microsoft & Xbox Live Auth Tokens (microsoft_accounts.json)
 * - Modrinth App (com.modrinth.theseus/settings/accounts.json, state.json)
 * - PrismLauncher (PrismLauncher/accounts.json)
 * - MultiMC (MultiMC/accounts.json)
 * - Badlion Client (Badlion Client/launcher/accounts.json)
 * - Lunar Client (Lunar Client/offline/multiver/accounts.json)
 * - Essential Mod (essential/microsoft_accounts.json)
 */
public final class FilesystemAccountGuard {

    private static final List<String> SENSITIVE_ACCOUNT_SIGNATURES = List.of(
            "launcher_accounts.json",
            "launcher_profiles.json",
            "microsoft_accounts.json",
            "prismlauncher/accounts",
            "multimc/accounts",
            "com.modrinth.theseus/settings/accounts",
            "com.modrinth.theseus/settings/state",
            "badlion client/launcher/accounts",
            "badlionclient/launcher/accounts",
            "lunar client/offline/multiver/accounts",
            "lunarclient/offline/multiver/accounts",
            ".minecraft/launcher_accounts",
            "essential/microsoft_accounts"
    );

    private static final Set<String> ALLOWED_ACCOUNT_MANAGERS = Set.of(
            "authme",
            "in-game-account-switcher",
            "reauth"
    );

    private static volatile boolean active = false;

    public static void install(Config config, ThreatHandler threatHandler) {
        if (!config.enabled || !config.filesystemGuard.enabled) {
            return;
        }
        active = true;
    }

    /**
     * Evaluates whether a given file path string targets sensitive launcher credentials.
     */
    public static boolean isSensitiveCredentialPath(String pathStr) {
        if (pathStr == null || pathStr.isBlank()) {
            return false;
        }
        String normalized = pathStr.replace('\\', '/').toLowerCase(Locale.ROOT);
        for (String sig : SENSITIVE_ACCOUNT_SIGNATURES) {
            if (normalized.contains(sig)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Evaluates whether a given Path targets sensitive launcher credentials.
     */
    public static boolean isSensitiveCredentialPath(Path path) {
        if (path == null) {
            return false;
        }
        return isSensitiveCredentialPath(path.toString());
    }

    /**
     * Checks if a mod is permitted to perform account management operations.
     */
    public static boolean isAllowedAccountManager(String modId) {
        if (modId == null) return false;
        return ALLOWED_ACCOUNT_MANAGERS.contains(modId.toLowerCase(Locale.ROOT));
    }

    public static boolean isActive() {
        return active;
    }
}
