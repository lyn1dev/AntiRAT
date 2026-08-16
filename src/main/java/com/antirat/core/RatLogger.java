package com.antirat.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/** Appends timestamped events to {@code logs/antirat.log}. */
public final class RatLogger {

    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final Path file;

    public RatLogger(Path gameDir) {
        this.file = gameDir.resolve("logs").resolve("antirat.log");
    }

    public void log(String message) {
        try {
            Files.createDirectories(file.getParent());
            String line = TIMESTAMP.format(LocalDateTime.now()) + " " + message + System.lineSeparator();
            Files.writeString(file, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // logging must never crash the game
        }
    }
}
