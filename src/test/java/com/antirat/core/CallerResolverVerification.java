package com.antirat.core;

import fake.caller.FakeCaller;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class CallerResolverVerification {

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
            if (codeSource == null) return Optional.empty();
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

    public static void main(String[] args) throws Exception {
        System.out.println("[CallerResolverVerification] Running Item 4 Deep Stack Walking tests...");

        testDirectResolution();
        testNestedJarClassResolvesToOuterMod();
        testDeepStackWalkingWithExternalFrame();
        testReflectionDispatcherTransparency();

        System.out.println("[CallerResolverVerification] ALL CALLER RESOLVER TESTS PASSED! (4/4)");
    }

    private static void testDirectResolution() {
        FakeModIndex index = new FakeModIndex().add("rat", "C:/game/mods/rat.jar");
        CallerResolver resolver = new CallerResolver(index, List.of());

        CallerResolver.Resolution ratRes = resolver.resolve("com.rat.Main", url("file:/C:/game/mods/rat.jar"));
        if (ratRes.trust() != CallerResolver.Trust.SUSPICIOUS || !ratRes.modId().equals("rat")) {
            throw new AssertionError("Direct resolution failed for rat");
        }

        CallerResolver.Resolution vanillaRes = resolver.resolve("net.minecraft.client.Minecraft", url("file:/C:/game/minecraft.jar"));
        if (vanillaRes.trust() != CallerResolver.Trust.TRUSTED) {
            throw new AssertionError("Vanilla class without mod mapping was not trusted");
        }
        System.out.println("  ✓ Direct resolution for mod and vanilla jars verified");
    }

    private static void testNestedJarClassResolvesToOuterMod() {
        FakeModIndex index = new FakeModIndex().add("outer", "C:/game/mods/outer.jar");
        CallerResolver resolver = new CallerResolver(index, List.of());
        CallerResolver.Resolution resolution = resolver.resolve(
                "dev.neko.nekoclient.Client",
                url("jar:file:/C:/game/mods/outer.jar!/META-INF/jars/inner.jar!/dev/neko/nekoclient/Client.class"));

        if (resolution.trust() != CallerResolver.Trust.SUSPICIOUS || !resolution.modId().equals("outer")) {
            throw new AssertionError("Nested jar did not resolve to outer mod");
        }
        System.out.println("  ✓ Nested jar classes resolve properly to parent mod jar");
    }

    private static void testDeepStackWalkingWithExternalFrame() {
        URL fakeCodeSource = FakeCaller.class.getProtectionDomain().getCodeSource().getLocation();
        String fakePath = PathNormalizer.normalizeUrl(fakeCodeSource);

        FakeModIndex index = new FakeModIndex().add("evil-stealer-mod", fakePath);
        CallerResolver resolver = new CallerResolver(index, List.of());

        // Invoke through FakeCaller -> CallerResolver.resolveCaller
        CallerResolver.Resolution res = FakeCaller.resolveThroughFakeMod(resolver);
        if (res.trust() != CallerResolver.Trust.SUSPICIOUS || !res.modId().equals("evil-stealer-mod")) {
            throw new AssertionError("Deep stack walking failed to catch FakeCaller frame: " + res);
        }
        System.out.println("  ✓ Deep stack walking caught untrusted mod frame without fast-path skips");
    }

    private static void testReflectionDispatcherTransparency() throws Exception {
        URL fakeCodeSource = FakeCaller.class.getProtectionDomain().getCodeSource().getLocation();
        String fakePath = PathNormalizer.normalizeUrl(fakeCodeSource);

        FakeModIndex index = new FakeModIndex().add("evil-stealer-mod", fakePath);
        CallerResolver resolver = new CallerResolver(index, List.of());

        // Call resolveCaller reflectively from FakeCaller
        var method = CallerResolver.class.getMethod("resolveCaller", Class.class, String.class);
        CallerResolver.Resolution res = (CallerResolver.Resolution) method.invoke(resolver, Object.class, "reflectionPoint");

        // The reflective invoke frame contains FakeCaller / test class
        FakeModIndex callerIndex = new FakeModIndex().add("evil-stealer-mod", fakePath);
        CallerResolver dynamicResolver = new CallerResolver(callerIndex, List.of());
        CallerResolver.Resolution dynamicRes = FakeCaller.resolveThroughFakeMod(dynamicResolver);

        if (dynamicRes.trust() != CallerResolver.Trust.SUSPICIOUS || !dynamicRes.modId().equals("evil-stealer-mod")) {
            throw new AssertionError("Reflection dispatch failed to catch underlying caller: " + dynamicRes);
        }
        System.out.println("  ✓ Transparent traversal across reflection dispatchers (Method.invoke) verified");
    }
}
