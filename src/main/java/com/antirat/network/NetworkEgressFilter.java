package com.antirat.network;

import com.antirat.core.Config;
import com.antirat.core.ThreatHandler;

import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * JVM-wide network egress filter installed as the default {@link ProxySelector}.
 *
 * Intercepts outbound HTTP/HTTPS calls made via standard Java networking libraries
 * (HttpURLConnection, HttpClient, OkHttp, etc.) and halts/blocks connections
 * to known Discord webhooks, Telegram bots, and data drop endpoints.
 */
public final class NetworkEgressFilter extends ProxySelector {

    private static volatile boolean installed = false;

    private final ProxySelector parent;
    private final ThreatHandler threatHandler;
    private final Config config;

    public NetworkEgressFilter(ProxySelector parent, ThreatHandler threatHandler, Config config) {
        this.parent = parent;
        this.threatHandler = threatHandler;
        this.config = config;
    }

    /**
     * Installs the NetworkEgressFilter as the global JVM default ProxySelector.
     */
    public static synchronized void install(Config config, ThreatHandler threatHandler) {
        if (installed || !config.enabled || !config.egressFilter.enabled) {
            return;
        }
        ProxySelector current = ProxySelector.getDefault();
        ProxySelector filter = new NetworkEgressFilter(current, threatHandler, config);
        ProxySelector.setDefault(filter);
        installed = true;
    }

    @Override
    public List<Proxy> select(URI uri) {
        if (uri == null) {
            return delegateSelect(null);
        }

        String host = uri.getHost();
        if (host == null) {
            return delegateSelect(uri);
        }

        if (isBlockedEndpoint(uri)) {
            String accessPoint = "NetworkEgress#" + host;
            boolean handled = false;
            if (threatHandler != null) {
                handled = threatHandler.checkAndRespond(NetworkEgressFilter.class, accessPoint);
            }
            if (!handled) {
                System.err.println("[AntiRAT] [EGRESS BLOCKED] Intercepted unauthorized connection to: " + uri);
            }
            throw new SecurityException("AntiRAT: Blocked unauthorized outbound exfiltration attempt to " + host);
        }

        return delegateSelect(uri);
    }

    @Override
    public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
        if (parent != null) {
            parent.connectFailed(uri, sa, ioe);
        }
    }

    /**
     * Evaluates whether the destination URI is a known exfiltration/webhook endpoint.
     */
    public static boolean isBlockedEndpoint(URI uri) {
        if (uri == null || uri.getHost() == null) {
            return false;
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        String path = uri.getPath() != null ? uri.getPath().toLowerCase(Locale.ROOT) : "";
        String full = uri.toString().toLowerCase(Locale.ROOT);

        // Discord webhooks
        if (host.endsWith("discord.com") || host.endsWith("discordapp.com")) {
            if (path.contains("/webhooks/") || full.contains("/webhooks/")) {
                return true;
            }
        }

        // Telegram Bot API
        if (host.equals("api.telegram.org") && (path.contains("/bot") || full.contains("/bot"))) {
            return true;
        }

        // Dedicated Webhook & C2 collection services
        if (host.equals("webhook.site") || host.endsWith(".webhook.site")) {
            return true;
        }
        if (host.equals("transfer.sh") || host.endsWith(".transfer.sh")) {
            return true;
        }
        if (host.equals("gofile.io") || host.endsWith(".gofile.io")) {
            return true;
        }
        if (host.endsWith("ngrok-free.app") || host.endsWith("ngrok.io")) {
            return true;
        }
        if (host.contains("pastebin.com") && (path.contains("/raw/") || path.contains("/api"))) {
            return true;
        }
        if (host.contains("hastebin.com") && (path.contains("/raw/") || path.contains("/documents"))) {
            return true;
        }
        if (host.equals("anonfiles.com") || host.equals("filebin.net")) {
            return true;
        }

        return false;
    }

    private List<Proxy> delegateSelect(URI uri) {
        if (parent != null) {
            return parent.select(uri);
        }
        return Collections.singletonList(Proxy.NO_PROXY);
    }
}
