package com.antirat.core;

import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PathNormalizerTest {

    @Test
    void normalizesPlainJarUrl() throws MalformedURLException {
        assertEquals("C:/game/mods/rat.jar",
                PathNormalizer.normalizeUrl(new URL("file:/C:/game/mods/rat.jar")));
    }

    @Test
    void normalizesJarNestedUrl() throws MalformedURLException {
        assertEquals("C:/game/mods/rat.jar",
                PathNormalizer.normalizeUrl(new URL("jar:file:/C:/game/mods/rat.jar!/com/evil/Evil.class")));
    }

    @Test
    void decodesSpaces() throws MalformedURLException {
        assertEquals("C:/game/mods/my mod.jar",
                PathNormalizer.normalizeUrl(new URL("file:/C:/game/mods/my%20mod.jar")));
    }

    @Test
    void normalizesPathSeparators() {
        assertEquals("C:/game/mods/rat.jar", PathNormalizer.normalizePath(Path.of("C:\\game\\mods\\rat.jar")));
    }
}
