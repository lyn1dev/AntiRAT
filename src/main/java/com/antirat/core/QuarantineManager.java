package com.antirat.core;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Moves offending mod jars from {@code mods/} into {@code mods/.antirat-quarantine/}
 * and renames them {@code *.jar.disabled} so they are not loaded on the next launch.
 */
public final class QuarantineManager {

    public enum Result {
        QUARANTINED,
        SKIPPED_NESTED,
        SKIPPED_DEV,
        SKIPPED_NO_FILE,
        FAILED
    }

    public record Outcome(Result result, Path target, String detail) {
    }

    private final Path modsDir;

    public QuarantineManager(Path modsDir) {
        this.modsDir = modsDir;
    }

    public Outcome quarantine(String modId, String originPath) {
        if (originPath == null || originPath.isEmpty()) {
            return new Outcome(Result.SKIPPED_NO_FILE, null, "origin unknown for mod " + modId);
        }
        try {
            Path origin = Path.of(originPath);
            Path absolute = origin.toAbsolutePath().normalize();
            Path modsAbsolute = modsDir.toAbsolutePath().normalize();
            if (absolute.getParent() == null) {
                // Loom dev runs record the filesystem root as the origin; no jar
                // exists here, so quarantine degrades to an alert-only result.
                return new Outcome(Result.SKIPPED_DEV, null,
                        "origin is the filesystem root (Loom dev run); only real jars under the mods dir can be quarantined");
            }
            if (!absolute.startsWith(modsAbsolute)) {
                return new Outcome(Result.SKIPPED_NESTED, null, "origin outside mods dir (nested jar?)");
            }
            if (!Files.isRegularFile(absolute)) {
                return new Outcome(Result.SKIPPED_NO_FILE, null, "origin is not a regular file");
            }
            Path quarantineDir = modsAbsolute.resolve(".antirat-quarantine");
            Files.createDirectories(quarantineDir);
            String fileName = absolute.getFileName().toString();
            Path target = quarantineDir.resolve(fileName + ".disabled");
            try {
                Files.move(absolute, target, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(absolute, target, StandardCopyOption.REPLACE_EXISTING);
            }
            return new Outcome(Result.QUARANTINED, target, fileName);
        } catch (IOException e) {
            return new Outcome(Result.FAILED, null, String.valueOf(e));
        }
    }
}
