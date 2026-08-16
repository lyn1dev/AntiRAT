package com.antirat.core;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FilesystemAccountGuardTest {

    @Test
    void detectsOfficialLauncherAccounts() {
        assertTrue(FilesystemAccountGuard.isSensitiveCredentialPath("C:/Users/User/AppData/Roaming/.minecraft/launcher_accounts.json"));
        assertTrue(FilesystemAccountGuard.isSensitiveCredentialPath("C:\\Users\\User\\AppData\\Roaming\\.minecraft\\launcher_profiles.json"));
    }

    @Test
    void detectsMicrosoftAccountsToken() {
        assertTrue(FilesystemAccountGuard.isSensitiveCredentialPath("C:/Users/User/.minecraft/essential/microsoft_accounts.json"));
        assertTrue(FilesystemAccountGuard.isSensitiveCredentialPath("microsoft_accounts.json"));
    }

    @Test
    void detectsThirdPartyLauncherCredentials() {
        assertTrue(FilesystemAccountGuard.isSensitiveCredentialPath("C:/Users/User/AppData/Roaming/PrismLauncher/accounts.json"));
        assertTrue(FilesystemAccountGuard.isSensitiveCredentialPath("D:/MultiMC/accounts.json"));
        assertTrue(FilesystemAccountGuard.isSensitiveCredentialPath("C:/Users/User/AppData/Roaming/com.modrinth.theseus/settings/accounts.json"));
        assertTrue(FilesystemAccountGuard.isSensitiveCredentialPath("C:/Users/User/AppData/Roaming/com.modrinth.theseus/settings/state.json"));
        assertTrue(FilesystemAccountGuard.isSensitiveCredentialPath("C:/Users/User/AppData/Roaming/Badlion Client/launcher/accounts.json"));
        assertTrue(FilesystemAccountGuard.isSensitiveCredentialPath("C:/Users/User/.lunarclient/offline/multiver/accounts.json"));
    }

    @Test
    void allowsStandardModAndGameFiles() {
        assertFalse(FilesystemAccountGuard.isSensitiveCredentialPath("config/skyhanni.json"));
        assertFalse(FilesystemAccountGuard.isSensitiveCredentialPath("options.txt"));
        assertFalse(FilesystemAccountGuard.isSensitiveCredentialPath("assets/minecraft/textures/block/stone.png"));
        assertFalse(FilesystemAccountGuard.isSensitiveCredentialPath("mods/antirat-1.0.0.jar"));
    }

    @Test
    void identifiesLegitimateAccountManagers() {
        assertTrue(FilesystemAccountGuard.isAllowedAccountManager("authme"));
        assertTrue(FilesystemAccountGuard.isAllowedAccountManager("in-game-account-switcher"));
        assertTrue(FilesystemAccountGuard.isAllowedAccountManager("reauth"));
        assertFalse(FilesystemAccountGuard.isAllowedAccountManager("random_malicious_mod"));
    }
}
