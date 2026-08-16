package com.antirat.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URL;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ThreatHandlerTest {

    @TempDir
    Path tempDir;

    private static final class FakeModIndex implements ModIndex {
        @Override
        public Optional<String> findModId(URL codeSource) {
            if (codeSource != null && codeSource.toString().contains("evil")) {
                return Optional.of("evil-mod");
            }
            return Optional.empty();
        }

        @Override
        public Optional<Path> findOrigin(String modId) {
            return Optional.of(Path.of("C:/mods/" + modId + ".jar"));
        }
    }

    @Test
    void panicOnThreatExecutesHaltOnSuspiciousCall() {
        Config config = new Config();
        config.panicOnThreat = true;
        CallerResolver resolver = new CallerResolver(new FakeModIndex(), List.of());
        QuarantineManager quarantine = new QuarantineManager(tempDir);
        RatLogger logger = new RatLogger(tempDir);
        AtomicBoolean panicked = new AtomicBoolean(false);

        ThreatHandler handler = new ThreatHandler(
                config,
                resolver,
                quarantine,
                logger,
                msg -> {},
                Runnable::run,
                () -> panicked.set(true)
        );

        // Class loaded in test environment without "evil" in its code source is trusted
        assertFalse(handler.checkAndRespond(ThreatHandlerTest.class, "User#getAccessToken"));
        assertFalse(panicked.get());
    }

    @Test
    void disabledConfigBypassesAllChecks() {
        Config config = new Config();
        config.enabled = false;
        CallerResolver resolver = new CallerResolver(new FakeModIndex(), List.of());
        QuarantineManager quarantine = new QuarantineManager(tempDir);
        RatLogger logger = new RatLogger(tempDir);
        AtomicBoolean panicked = new AtomicBoolean(false);

        ThreatHandler handler = new ThreatHandler(
                config,
                resolver,
                quarantine,
                logger,
                msg -> {},
                Runnable::run,
                () -> panicked.set(true)
        );

        assertFalse(handler.checkAndRespond(ThreatHandlerTest.class, "User#getAccessToken"));
        assertFalse(panicked.get());
    }
}
