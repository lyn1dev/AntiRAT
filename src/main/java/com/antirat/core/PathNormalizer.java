package com.antirat.core;

import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;

/** Normalizes class code-source URLs and mod origin paths to comparable strings. */
public final class PathNormalizer {

    private PathNormalizer() {
    }

    /**
     * Normalizes a class code source URL to a plain absolute path string.
     * Handles jar:/file: forms, {@code !/} nested entries and URL-encoding.
     */
    public static String normalizeUrl(URL url) {
        String s = url.toExternalForm();
        if (s.startsWith("jar:")) {
            s = s.substring(4);
        }
        int bang = s.indexOf("!/");
        if (bang >= 0) {
            s = s.substring(0, bang);
        }
        if (s.startsWith("file:")) {
            s = s.substring(5);
        }
        try {
            s = URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ignored) {
            // keep raw value
        }
        s = s.replace('\\', '/');
        // URL form has a leading slash before the drive letter: /C:/...
        if (s.length() >= 3 && s.charAt(0) == '/' && s.charAt(2) == ':') {
            s = s.substring(1);
        }
        return stripTrailingSlash(s);
    }

    /** Normalizes a filesystem path to a comparable string. */
    public static String normalizePath(Path path) {
        try {
            return stripTrailingSlash(path.toAbsolutePath().normalize().toString().replace('\\', '/'));
        } catch (InvalidPathException e) {
            return null;
        }
    }

    private static String stripTrailingSlash(String s) {
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }
}
