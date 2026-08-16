package com.antirat.core;

import fake.caller.FakeCaller;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

public class ThreatHandlerVerification {

    public static void main(String[] args) throws Exception {
        System.out.println("[ThreatHandlerVerification] Running Item 2 Fail-Closed Panic & Engine Hardening tests...");
        Path tempDir = Files.createTempDirectory("antirat-threat-test");

        try {
            testPanicTriggeredOnSuspiciousCall(tempDir);
            testNoPanicWhenDisabled(tempDir);
            System.out.println("[ThreatHandlerVerification] ALL THREAT HANDLER TESTS PASSED! (2/2)");
        } finally {
            deleteRecursive(tempDir);
        }
    }

    private static void testPanicTriggeredOnSuspiciousCall(Path tempDir) {
        Config config = new Config();
        config.panicOnThreat = true;

        ModIndex evilIndex = new ModIndex() {
            @Override
            public Optional<String> findModId(URL codeSource) {
                return Optional.of("evil-rat");
            }

            @Override
            public Optional<Path> findOrigin(String modId) {
                return Optional.of(Path.of("C:/mods/evil-rat.jar"));
            }
        };

        CallerResolver resolver = new CallerResolver(evilIndex, List.of());
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

        boolean responded = FakeCaller.callGetAccessToken(handler);
        if (!responded) {
            throw new AssertionError("Expected checkAndRespond to return true for suspicious call");
        }
        if (!panicked.get()) {
            throw new AssertionError("Expected panicAction to be invoked on suspicious call when panicOnThreat is true");
        }
        System.out.println("  ✓ Panic halt triggered immediately on suspicious call from external mod frame");
    }

    private static void testNoPanicWhenDisabled(Path tempDir) {
        Config config = new Config();
        config.enabled = false;
        config.panicOnThreat = true;

        ModIndex evilIndex = new ModIndex() {
            @Override
            public Optional<String> findModId(URL codeSource) {
                return Optional.of("evil-rat");
            }

            @Override
            public Optional<Path> findOrigin(String modId) {
                return Optional.of(Path.of("C:/mods/evil-rat.jar"));
            }
        };

        CallerResolver resolver = new CallerResolver(evilIndex, List.of());
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

        boolean responded = FakeCaller.callGetAccessToken(handler);
        if (responded || panicked.get()) {
            throw new AssertionError("Disabled config must not respond or panic");
        }
        System.out.println("  ✓ Disabled config bypassed all checks cleanly");
    }

    private static void deleteRecursive(Path path) {
        try {
            if (Files.isDirectory(path)) {
                try (var s = Files.list(path)) {
                    s.forEach(ThreatHandlerVerification::deleteRecursive);
                }
            }
            Files.deleteIfExists(path);
        } catch (Exception ignored) {}
    }
}
