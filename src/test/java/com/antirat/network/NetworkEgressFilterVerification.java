package com.antirat.network;

import com.antirat.core.CallerResolver;
import com.antirat.core.Config;
import com.antirat.core.ModIndex;
import com.antirat.core.QuarantineManager;
import com.antirat.core.RatLogger;
import com.antirat.core.ThreatHandler;

import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class NetworkEgressFilterVerification {

    public static void main(String[] args) throws Exception {
        System.out.println("[NetworkEgressFilterVerification] Running Item 3 Network Egress Filtering tests...");
        Path tempDir = Files.createTempDirectory("antirat-egress-test");

        try {
            testBlockedEndpointPatterns();
            testProxySelectionAndSecurityException(tempDir);
            System.out.println("[NetworkEgressFilterVerification] ALL NETWORK EGRESS TESTS PASSED! (2/2)");
        } finally {
            deleteRecursive(tempDir);
        }
    }

    private static void testBlockedEndpointPatterns() {
        assertBlocked("https://discord.com/api/webhooks/123456/token", true);
        assertBlocked("https://discordapp.com/api/webhooks/123456/token", true);
        assertBlocked("https://api.telegram.org/bot123456:ABC/sendMessage", true);
        assertBlocked("https://webhook.site/uuid-1234", true);
        assertBlocked("https://transfer.sh/file.txt", true);
        assertBlocked("https://gofile.io/d/12345", true);
        assertBlocked("https://abc.ngrok-free.app/collect", true);
        assertBlocked("https://pastebin.com/raw/something", true);
        assertBlocked("https://hastebin.com/raw/something", true);

        // Clean URIs
        assertBlocked("https://sessionserver.mojang.com/session/minecraft/join", false);
        assertBlocked("https://authserver.mojang.com/authenticate", false);
        assertBlocked("https://api.modrinth.com/v2/version", false);
        assertBlocked("https://curseforge.com/api", false);
        System.out.println("  ✓ Blocked and permitted endpoint patterns verified correctly");
    }

    private static void assertBlocked(String url, boolean expected) {
        boolean actual = NetworkEgressFilter.isBlockedEndpoint(URI.create(url));
        if (actual != expected) {
            throw new AssertionError("Expected isBlockedEndpoint(" + url + ") to be " + expected + ", got " + actual);
        }
    }

    private static void testProxySelectionAndSecurityException(Path tempDir) {
        Config config = new Config();
        config.panicOnThreat = false;

        ThreatHandler handler = new ThreatHandler(
                config,
                new CallerResolver(new ModIndex() {
                    @Override
                    public Optional<String> findModId(java.net.URL codeSource) {
                        return Optional.empty();
                    }
                    @Override
                    public Optional<Path> findOrigin(String modId) {
                        return Optional.empty();
                    }
                }, List.of()),
                new QuarantineManager(tempDir),
                new RatLogger(tempDir),
                msg -> {},
                Runnable::run
        );

        ProxySelector mockParent = new ProxySelector() {
            @Override
            public List<Proxy> select(URI uri) {
                return Collections.singletonList(Proxy.NO_PROXY);
            }
            @Override
            public void connectFailed(URI uri, SocketAddress sa, java.io.IOException ioe) {}
        };

        NetworkEgressFilter filter = new NetworkEgressFilter(mockParent, handler, config);

        // Allowed URI passes through
        List<Proxy> proxies = filter.select(URI.create("https://sessionserver.mojang.com/session/minecraft/join"));
        if (proxies.size() != 1 || proxies.get(0) != Proxy.NO_PROXY) {
            throw new AssertionError("Allowed URI failed to pass through proxy filter");
        }

        // Blocked URI must throw SecurityException
        boolean caught = false;
        try {
            filter.select(URI.create("https://discord.com/api/webhooks/1234/secret"));
        } catch (SecurityException e) {
            caught = true;
        }

        if (!caught) {
            throw new AssertionError("Expected SecurityException when selecting proxy for Discord webhook");
        }
        System.out.println("  ✓ Unauthorized webhook traffic intercepted and aborted with SecurityException");
    }

    private static void deleteRecursive(Path path) {
        try {
            if (Files.isDirectory(path)) {
                try (var s = Files.list(path)) {
                    s.forEach(NetworkEgressFilterVerification::deleteRecursive);
                }
            }
            Files.deleteIfExists(path);
        } catch (Exception ignored) {}
    }
}
