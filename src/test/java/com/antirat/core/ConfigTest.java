package com.antirat.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigTest {

    @TempDir
    Path tempDir;

    @Test
    void createsDefaultConfigWhenMissing() throws Exception {
        Config config = Config.load(tempDir);
        assertTrue(config.enabled);
        assertTrue(config.quarantine.enabled);
        assertTrue(config.alert.title);
        assertTrue(config.alert.chat);
        assertTrue(config.log.enabled);
        assertFalse(config.debug);
        assertTrue(Files.exists(tempDir.resolve("antirat.json")));
    }

    @Test
    void parsesCustomConfig() throws Exception {
        Files.writeString(tempDir.resolve("antirat.json"), """
                {
                  "enabled": false,
                  "whitelistModIds": ["good-mod"],
                  "quarantine": { "enabled": false },
                  "alert": { "title": false, "chat": true },
                  "log": { "enabled": false },
                  "debug": true
                }
                """);
        Config config = Config.load(tempDir);
        assertFalse(config.enabled);
        assertEquals(1, config.whitelistModIds.size());
        assertEquals("good-mod", config.whitelistModIds.get(0));
        assertFalse(config.quarantine.enabled);
        assertFalse(config.alert.title);
        assertTrue(config.alert.chat);
        assertFalse(config.log.enabled);
        assertTrue(config.debug);
    }

    @Test
    void brokenJsonFallsBackToDefaults() throws Exception {
        Files.writeString(tempDir.resolve("antirat.json"), "{ not json !!");
        Config config = Config.load(tempDir);
        assertTrue(config.enabled);
        assertTrue(config.quarantine.enabled);
    }
}
