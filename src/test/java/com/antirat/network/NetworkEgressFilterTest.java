package com.antirat.network;

import com.antirat.core.CallerResolver;
import com.antirat.core.Config;
import com.antirat.core.ModIndex;
import com.antirat.core.QuarantineManager;
import com.antirat.core.RatLogger;
import com.antirat.core.ThreatHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NetworkEgressFilterTest {

    @TempDir
    Path tempDir;

    @Test
    void identifiesBlockedEndpointsCorrectly() {
        assertTrue(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://discord.com/api/webhooks/123456/token")));
        assertTrue(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://discordapp.com/api/webhooks/123456/token")));
        assertTrue(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://api.telegram.org/bot123456:ABC/sendMessage")));
        assertTrue(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://webhook.site/uuid-1234")));
        assertTrue(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://transfer.sh/file.txt")));
        assertTrue(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://gofile.io/d/12345")));
        assertTrue(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://abc.ngrok-free.app/collect")));
        assertTrue(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://pastebin.com/raw/something")));
        assertTrue(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://hastebin.com/raw/something")));

        // Legitimate endpoints must NOT be blocked
        assertFalse(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://sessionserver.mojang.com/session/minecraft/join")));
        assertFalse(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://authserver.mojang.com/authenticate")));
        assertFalse(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://api.modrinth.com/v2/version")));
        assertFalse(NetworkEgressFilter.isBlockedEndpoint(URI.create("https://curseforge.com/api")));
    }

    @Test
    void selectThrowsSecurityExceptionOnBlockedEndpoint() {
        Config config = new Config();
        config.panicOnThreat = false;
        AtomicBoolean threatCalled = new AtomicBoolean(false);

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
        assertEquals(1, proxies.size());

        // Blocked URI triggers SecurityException
        assertThrows(SecurityException.class, () ->
                filter.select(URI.create("https://discord.com/api/webhooks/1234/secret"))
        );
    }
}
