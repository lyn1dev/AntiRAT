package com.antirat.core;

import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CallerResolverTest {

    private static final class FakeModIndex implements ModIndex {
        private final Map<String, String> byPath = new HashMap<>();
        private final Map<String, String> origins = new HashMap<>();

        FakeModIndex add(String modId, String path) {
            byPath.put(PathNormalizer.normalizePath(Path.of(path)), modId);
            origins.put(modId, path);
            return this;
        }

        @Override
        public Optional<String> findModId(URL codeSource) {
            return Optional.ofNullable(byPath.get(PathNormalizer.normalizeUrl(codeSource)));
        }

        @Override
        public Optional<Path> findOrigin(String modId) {
            String origin = origins.get(modId);
            return origin == null ? Optional.empty() : Optional.of(Path.of(origin));
        }
    }

    private static URL url(String s) {
        try {
            return new URL(s);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void gameClassFromGameJarIsTrusted() {
        CallerResolver resolver = new CallerResolver(new FakeModIndex(), List.of());
        assertEquals(CallerResolver.Trust.TRUSTED,
                resolver.resolve("net.minecraft.client.Minecraft", url("file:/C:/game/minecraft-client.jar")).trust());
    }

    @Test
    void gamePackageFromModJarIsStillSuspicious() {
        FakeModIndex index = new FakeModIndex().add("evil", "C:/game/mods/evil.jar");
        CallerResolver resolver = new CallerResolver(index, List.of());
        CallerResolver.Resolution resolution = resolver.resolve("net.minecraft.spoofed.Evil", url("file:/C:/game/mods/evil.jar"));
        assertEquals(CallerResolver.Trust.SUSPICIOUS, resolution.trust());
        assertEquals("evil", resolution.modId());
    }

    @Test
    void suspiciousModIsReported() {
        FakeModIndex index = new FakeModIndex().add("rat", "C:/game/mods/rat.jar");
        CallerResolver resolver = new CallerResolver(index, List.of());
        CallerResolver.Resolution resolution = resolver.resolve("com.rat.Main", url("file:/C:/game/mods/rat.jar"));
        assertEquals(CallerResolver.Trust.SUSPICIOUS, resolution.trust());
        assertEquals("rat", resolution.modId());
        assertEquals("C:/game/mods/rat.jar", PathNormalizer.normalizePath(Path.of(resolution.origin())));
    }

    @Test
    void whitelistedModIsTrusted() {
        FakeModIndex index = new FakeModIndex().add("trusted", "C:/game/mods/trusted.jar");
        CallerResolver resolver = new CallerResolver(index, List.of("trusted"));
        CallerResolver.Resolution resolution = resolver.resolve("com.trusted.Main", url("file:/C:/game/mods/trusted.jar"));
        assertEquals(CallerResolver.Trust.TRUSTED, resolution.trust());
        assertEquals("trusted", resolution.modId());
    }

    @Test
    void libraryWithoutModContainerIsTrusted() {
        CallerResolver resolver = new CallerResolver(new FakeModIndex(), List.of());
        assertEquals(CallerResolver.Trust.TRUSTED,
                resolver.resolve("com.google.gson.Gson", url("file:/C:/game/libraries/gson.jar")).trust());
    }

    @Test
    void jdkClassWithoutCodeSourceIsTrusted() {
        CallerResolver resolver = new CallerResolver(new FakeModIndex(), List.of());
        assertEquals(CallerResolver.Trust.TRUSTED, resolver.resolve("java.lang.Object", null).trust());
    }

    @Test
    void nestedJarClassResolvesToOuterMod() {
        FakeModIndex index = new FakeModIndex().add("outer", "C:/game/mods/outer.jar");
        CallerResolver resolver = new CallerResolver(index, List.of());
        CallerResolver.Resolution resolution = resolver.resolve(
                "dev.neko.nekoclient.Client",
                url("jar:file:/C:/game/mods/outer.jar!/META-INF/jars/inner.jar!/dev/neko/nekoclient/Client.class"));
        assertEquals(CallerResolver.Trust.SUSPICIOUS, resolution.trust());
        assertEquals("outer", resolution.modId());
    }
}
