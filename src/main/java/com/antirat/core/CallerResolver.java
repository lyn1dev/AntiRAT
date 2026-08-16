package com.antirat.core;

import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Identifies the mod that triggered a hooked session-token access.
 *
 * The stack is walked from the hook frame upwards; vanilla/JDK frames are
 * transparent, the first frame that resolves to a non-whitelisted mod makes
 * the whole call suspicious. If no frame belongs to a mod, the call is trusted
 * (vanilla authentication/skin flows keep working).
 */
public final class CallerResolver {

    public enum Trust {
        TRUSTED,
        SUSPICIOUS
    }

    public record Resolution(Trust trust, String modId, String origin) {
    }

    private static final Set<String> GAME_PACKAGES = Set.of("net.minecraft", "com.mojang");
    private static final int MAX_FRAMES = 64;

    private final ModIndex modIndex;
    private final Set<String> whitelistedModIds;

    public CallerResolver(ModIndex modIndex, List<String> whitelistedModIds) {
        this.modIndex = modIndex;
        this.whitelistedModIds = Set.copyOf(whitelistedModIds);
    }

    /**
     * Walks the current thread's stack and resolves the call owner.
     *
     * @param hookTarget the class the mixin hook is injected into (skipped)
     * @param accessPoint human-readable hook description (logging only)
     */
    public Resolution resolveCaller(Class<?> hookTarget, String accessPoint) {
        List<Class<?>> frames = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(stream -> stream
                        .map(StackWalker.StackFrame::getDeclaringClass)
                        .filter(frame -> frame != hookTarget)
                        .filter(frame -> !frame.getName().startsWith("com.antirat."))
                        .limit(MAX_FRAMES)
                        .collect(Collectors.toList()));
        // Fast path: the first non-hook frame is a vanilla/library class that does not
        // belong to any mod. Normal login/auth flows never need a full stack walk.
        if (!frames.isEmpty()) {
            Class<?> firstFrame = frames.get(0);
            String firstName = firstFrame.getName();
            if (GAME_PACKAGES.stream().anyMatch(firstName::startsWith)) {
                Resolution first = resolve(firstName, codeSourceOf(firstFrame));
                if (first.trust() == Trust.TRUSTED) {
                    return new Resolution(Trust.TRUSTED, "", "");
                }
            }
        }
        for (Class<?> frame : frames) {
            Resolution resolution = resolve(frame.getName(), codeSourceOf(frame));
            if (resolution.trust() == Trust.SUSPICIOUS) {
                return resolution;
            }
            // TRUSTED frames are transparent: keep walking until a mod frame is found.
        }
        return new Resolution(Trust.TRUSTED, "", "");
    }

    /**
     * Resolves a single class to its owning mod.
     *
     * @param className  fully qualified class name
     * @param codeSource the class's code source location, may be null
     */
    public Resolution resolve(String className, URL codeSource) {
        if (codeSource == null) {
            // JDK/other classes without a code source are trusted.
            return new Resolution(Trust.TRUSTED, "", "");
        }
        Optional<String> modId = modIndex.findModId(codeSource);
        if (modId.isEmpty()) {
            // Game jar, libraries, JDK: not part of any mod.
            return new Resolution(Trust.TRUSTED, "", "");
        }
        String id = modId.get();
        String origin = modIndex.findOrigin(id).map(java.nio.file.Path::toString).orElse("");
        if (whitelistedModIds.contains(id)) {
            return new Resolution(Trust.TRUSTED, id, origin);
        }
        return new Resolution(Trust.SUSPICIOUS, id, origin);
    }

    private static URL codeSourceOf(Class<?> clazz) {
        ProtectionDomain domain = clazz.getProtectionDomain();
        if (domain == null) {
            return null;
        }
        CodeSource codeSource = domain.getCodeSource();
        return codeSource == null ? null : codeSource.getLocation();
    }
}
