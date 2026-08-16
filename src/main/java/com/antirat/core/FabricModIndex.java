package com.antirat.core;

import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.fabricmc.loader.api.metadata.ModOrigin;

import java.net.URL;
import java.net.MalformedURLException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * ModIndex backed by the Fabric loader's mod registry.
 *
 * Resolution is based on the class code source location compared against each
 * mod container's origin path (fabric-loader 0.19.x has no class-to-mod API).
 */
public final class FabricModIndex implements ModIndex {

    private final Map<String, Path> origins = new HashMap<>();
    private final Map<String, String> byNormalizedPath = new HashMap<>();
    private volatile boolean initialized;

    private void ensureInitialized() {
        if (initialized) {
            return;
        }
        synchronized (this) {
            if (initialized) {
                return;
            }
            for (ModContainer container : FabricLoader.getInstance().getAllMods()) {
                String modId = container.getMetadata().getId();
                if (modId.equals("minecraft") || container.getOrigin().getKind() == ModOrigin.Kind.UNKNOWN) {
                    // The game jar itself is a built-in container, not a mod to quarantine.
                    continue;
                }
                // Dev runs: Loom registers build/resources/main as the origin while
                // classes live in build/classes/java/main, so index every root path.
                // Jar runs: the jar file itself is a root path.
                try {
                    for (Path root : container.getRootPaths()) {
                        registerPath(modId, root);
                    }
                } catch (RuntimeException ignored) {
                    // Some origin kinds expose no root paths; index what we can.
                }
                try {
                    for (Path origin : container.getOrigin().getPaths()) {
                        registerPath(modId, origin);
                    }
                } catch (RuntimeException ignored) {
                    // NESTED jars have no origin paths in fabric-loader 0.19.x;
                    // their classes still match through the outer jar's roots.
                }
            }
            initialized = true;
        }
    }

    private void registerPath(String modId, Path path) {
        String normalized = normalizeLocation(path);
        if (normalized != null) {
            origins.putIfAbsent(modId, path);
            byNormalizedPath.putIfAbsent(normalized, modId);
        }
    }

    /** Normalizes a mod root/origin path to the same form as a class code-source URL. */
    private static String normalizeLocation(Path path) {
        String raw = path.toString();
        try {
            if (raw.startsWith("jar:")) {
                // jar:file:/C:/mods/foo.jar!/ -> file:/C:/mods/foo.jar
                String inner = raw.substring(4);
                int bang = inner.indexOf("!/");
                if (bang >= 0) {
                    inner = inner.substring(0, bang);
                }
                return PathNormalizer.normalizeUrl(new URL(inner));
            }
            return PathNormalizer.normalizePath(path);
        } catch (MalformedURLException | java.nio.file.InvalidPathException e) {
            return null;
        }
    }

    @Override
    public Optional<String> findModId(URL codeSource) {
        ensureInitialized();
        String normalized = PathNormalizer.normalizeUrl(codeSource);
        if (normalized.isEmpty()) {
            return Optional.empty();
        }
        String direct = byNormalizedPath.get(normalized);
        if (direct != null) {
            return Optional.of(direct);
        }
        // Prefix fallback: dev classes dirs, nested jar entries inside an outer mod jar.
        for (Map.Entry<String, String> entry : byNormalizedPath.entrySet()) {
            String origin = entry.getKey();
            if (normalized.startsWith(origin + "/") || origin.startsWith(normalized + "/")) {
                return Optional.of(entry.getValue());
            }
        }
        return Optional.empty();
    }

    @Override
    public Optional<Path> findOrigin(String modId) {
        ensureInitialized();
        Path origin = origins.get(modId);
        return origin == null ? Optional.empty() : Optional.of(origin);
    }
}
