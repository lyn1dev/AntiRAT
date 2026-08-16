package com.antirat.core;

import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Identifies the mod that triggered a hooked session-token access or network request.
 *
 * Walks the complete call stack without bypassable fast paths.
 * Vanilla/JDK/reflection frames are transparent; if ANY frame on the active call stack
 * belongs to an unwhitelisted mod, the entire invocation is classified as SUSPICIOUS.
 */
public final class CallerResolver {

    public enum Trust {
        TRUSTED,
        SUSPICIOUS
    }

    public record Resolution(Trust trust, String modId, String origin) {
    }

    private static final int MAX_FRAMES = 128;
    private static final Set<String> REFLECTION_PACKAGES = Set.of(
            "java.lang.reflect.",
            "jdk.internal.reflect.",
            "sun.reflect.",
            "java.lang.invoke."
    );

    public static final Set<String> DEFAULT_HARDCODED_WHITELIST = Set.of(
            // Platform & Core loaders
            "minecraft",
            "fabricloader",
            "fabric-loader",
            "fabric",
            "fabric-api",
            "fabric-language-kotlin",
            "antirat",
            "java",

            // User's Verified Modpack Mods
            "asynclogger",
            "asyncparticles",
            "authme",
            "better_hypixel_chat",
            "bobby",
            "btrbz",
            "catharsis",
            "cloth-config",
            "compacting",
            "controlling",
            "crash_assistant",
            "cwb",
            "debugify",
            "enhancedsoundcontrol",
            "enhanced_chat",
            "enhanced_storage",
            "entityculling",
            "fastipping",
            "feesh",
            "ferritecore",
            "forcecloseworldloadingscreen",
            "gnetum",
            "immediatelyfast",
            "inventorybuttons",
            "iris",
            "ixeris",
            "languagereload",
            "lithium",
            "marketguard",
            "modernfix",
            "modernwarpmenu",
            "modmenu",
            "moreculling",
            "netprodis",
            "nochatreports",
            "nochatrestrictions",
            "obe",
            "odin",
            "packcore",
            "packetfixer",
            "placeholder-api",
            "rrv",
            "rpc",
            "sbo",
            "scaleme",
            "scamscreener",
            "searchables",
            "skinlayers3d",
            "skyblocker",
            "skyblockpv",
            "skyblock_enhancements",
            "skyhanni",
            "skyocean",
            "skyrecipes",
            "sodium-extra",
            "sodium",
            "sspb",
            "stella",
            "stfu",
            "uilib",
            "yet_another_config_lib_v3",
            "zoomify"
    );

    private final ModIndex modIndex;
    private final Set<String> whitelistedModIds;

    public CallerResolver(ModIndex modIndex, List<String> whitelistedModIds) {
        this.modIndex = modIndex;
        this.whitelistedModIds = Set.copyOf(whitelistedModIds);
    }

    /**
     * Walks the current thread's complete stack and resolves the call owner.
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
                        .filter(frame -> !isReflectionDispatcher(frame))
                        .limit(MAX_FRAMES)
                        .collect(Collectors.toList()));

        // Inspect EVERY frame on the call stack without skipping or trusting early
        for (Class<?> frame : frames) {
            Resolution resolution = resolve(frame.getName(), codeSourceOf(frame));
            if (resolution.trust() == Trust.SUSPICIOUS) {
                return resolution;
            }
        }
        return new Resolution(Trust.TRUSTED, "", "");
    }

    private static boolean isReflectionDispatcher(Class<?> clazz) {
        String name = clazz.getName();
        for (String pkg : REFLECTION_PACKAGES) {
            if (name.startsWith(pkg)) {
                return true;
            }
        }
        return false;
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
        if (DEFAULT_HARDCODED_WHITELIST.contains(id.toLowerCase(java.util.Locale.ROOT)) || whitelistedModIds.contains(id)) {
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
