package com.antirat.core;

import java.net.URL;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Abstraction over the Fabric mod registry so the caller-resolution logic can
 * be unit-tested without a running Fabric loader.
 */
public interface ModIndex {

    /**
     * Returns the mod id owning the given code source location, if any.
     *
     * @param codeSource location of a loaded class (jar, classes dir, nested jar entry)
     */
    Optional<String> findModId(URL codeSource);

    /** Returns the origin path (usually the jar file) of a mod id, if known. */
    Optional<Path> findOrigin(String modId);
}
