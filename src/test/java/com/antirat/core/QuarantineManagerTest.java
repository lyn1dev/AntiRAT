package com.antirat.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QuarantineManagerTest {

    @TempDir
    Path tempDir;

    private Path modsDir() throws IOException {
        Path mods = tempDir.resolve("mods");
        Files.createDirectories(mods);
        return mods;
    }

    @Test
    void movesOffendingJarIntoQuarantine() throws IOException {
        Path mods = modsDir();
        Path jar = mods.resolve("rat.jar");
        Files.writeString(jar, "fake jar");
        QuarantineManager manager = new QuarantineManager(mods);

        QuarantineManager.Outcome outcome = manager.quarantine("rat", jar.toString());

        assertEquals(QuarantineManager.Result.QUARANTINED, outcome.result());
        assertFalse(Files.exists(jar));
        assertTrue(Files.exists(mods.resolve(".antirat-quarantine/rat.jar.disabled")));
    }

    @Test
    void originOutsideModsDirIsSkipped() throws IOException {
        Path mods = modsDir();
        Path elsewhere = tempDir.resolve("other").resolve("rat.jar");
        Files.createDirectories(elsewhere.getParent());
        Files.writeString(elsewhere, "fake");
        QuarantineManager manager = new QuarantineManager(mods);

        QuarantineManager.Outcome outcome = manager.quarantine("rat", elsewhere.toString());

        assertEquals(QuarantineManager.Result.SKIPPED_NESTED, outcome.result());
        assertTrue(Files.exists(elsewhere));
    }

    @Test
    void filesystemRootOriginIsDevSkipped() throws IOException {
        // Loom dev runs report the filesystem root as a mod's origin; there is
        // no jar to move, so quarantine must report a dedicated result.
        QuarantineManager manager = new QuarantineManager(modsDir());
        QuarantineManager.Outcome outcome = manager.quarantine("rat", Path.of("/").toString());
        assertEquals(QuarantineManager.Result.SKIPPED_DEV, outcome.result());
    }

    @Test
    void nonexistentOriginIsSkipped() throws IOException {
        QuarantineManager manager = new QuarantineManager(modsDir());
        QuarantineManager.Outcome outcome = manager.quarantine("rat", tempDir.resolve("mods/missing.jar").toString());
        assertEquals(QuarantineManager.Result.SKIPPED_NO_FILE, outcome.result());
    }

    @Test
    void emptyOriginIsSkipped() throws IOException {
        QuarantineManager manager = new QuarantineManager(modsDir());
        QuarantineManager.Outcome outcome = manager.quarantine("rat", "");
        assertEquals(QuarantineManager.Result.SKIPPED_NO_FILE, outcome.result());
    }

    @Test
    void lockedFileFailsGracefully() throws IOException {
        // On Windows a jar held open by the game cannot be moved; the manager
        // must degrade to a FAILED outcome instead of crashing.
        assumeTrue(System.getProperty("os.name").toLowerCase().contains("win"),
                "file-locking semantics are Windows-specific");
        Path mods = modsDir();
        Path jar = mods.resolve("rat.jar");
        Files.writeString(jar, "fake jar");
        try (FileInputStream locked = new FileInputStream(jar.toFile())) {
            QuarantineManager manager = new QuarantineManager(mods);
            QuarantineManager.Outcome outcome = manager.quarantine("rat", jar.toString());
            assertEquals(QuarantineManager.Result.FAILED, outcome.result());
        }
        assertTrue(Files.exists(jar), "locked jar must not be moved");
    }
}
