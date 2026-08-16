package com.antirat.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Configuration persisted to {@code config/antirat.json}. */
public final class Config {

    public boolean enabled = true;
    public List<String> whitelistModIds = new ArrayList<>();
    public boolean panicOnThreat = false;
    public Scanner scanner = new Scanner();
    public EgressFilter egressFilter = new EgressFilter();
    public Quarantine quarantine = new Quarantine();
    public Alert alert = new Alert();
    public Log log = new Log();
    public FilesystemGuard filesystemGuard = new FilesystemGuard();
    public ProcessSandbox processSandbox = new ProcessSandbox();
    public boolean debug = false;

    public static final class Scanner {
        public boolean enabled = true;
    }

    public static final class EgressFilter {
        public boolean enabled = true;
    }

    public static final class Quarantine {
        public boolean enabled = true;
    }

    public static final class Alert {
        public boolean title = true;
        public boolean chat = true;
    }

    public static final class Log {
        public boolean enabled = true;
    }

    public static final class FilesystemGuard {
        public boolean enabled = true;
    }

    public static final class ProcessSandbox {
        public boolean enabled = true;
    }

    public static Config load(Path configDir) {
        Path file = configDir.resolve("antirat.json");
        Config cfg = new Config();
        if (!Files.exists(file)) {
            save(configDir, cfg);
            return cfg;
        }
        try {
            String text = Files.readString(file);
            java.util.regex.Matcher mEnabled = java.util.regex.Pattern.compile("\"enabled\"\\s*:\\s*(true|false)").matcher(text);
            if (mEnabled.find()) {
                cfg.enabled = Boolean.parseBoolean(mEnabled.group(1));
            }
            int idx = text.indexOf("\"whitelistModIds\"");
            if (idx != -1) {
                int start = text.indexOf('[', idx);
                int end = text.indexOf(']', start);
                if (start != -1 && end != -1) {
                    String arr = text.substring(start + 1, end);
                    for (String part : arr.split(",")) {
                        String item = part.replace("\"", "").replace("\r", "").replace("\n", "").trim();
                        if (!item.isEmpty() && !cfg.whitelistModIds.contains(item)) {
                            cfg.whitelistModIds.add(item);
                        }
                    }
                }
            }
            java.util.regex.Matcher mPanic = java.util.regex.Pattern.compile("\"panicOnThreat\"\\s*:\\s*(true|false)").matcher(text);
            if (mPanic.find()) cfg.panicOnThreat = Boolean.parseBoolean(mPanic.group(1));

            java.util.regex.Matcher mDebug = java.util.regex.Pattern.compile("\"debug\"\\s*:\\s*(true|false)").matcher(text);
            if (mDebug.find()) cfg.debug = Boolean.parseBoolean(mDebug.group(1));

            parseSection(text, "scanner", b -> cfg.scanner.enabled = b);
            parseSection(text, "egressFilter", b -> cfg.egressFilter.enabled = b);
            parseSection(text, "quarantine", b -> cfg.quarantine.enabled = b);
            parseSection(text, "log", b -> cfg.log.enabled = b);
            parseSection(text, "filesystemGuard", b -> cfg.filesystemGuard.enabled = b);
            parseSection(text, "processSandbox", b -> cfg.processSandbox.enabled = b);

            int alertIdx = text.indexOf("\"alert\"");
            if (alertIdx != -1) {
                int start = text.indexOf('{', alertIdx);
                int end = text.indexOf('}', start);
                if (start != -1 && end != -1) {
                    String alertSection = text.substring(start, end + 1);
                    java.util.regex.Matcher mTitle = java.util.regex.Pattern.compile("\"title\"\\s*:\\s*(true|false)").matcher(alertSection);
                    if (mTitle.find()) cfg.alert.title = Boolean.parseBoolean(mTitle.group(1));
                    java.util.regex.Matcher mChat = java.util.regex.Pattern.compile("\"chat\"\\s*:\\s*(true|false)").matcher(alertSection);
                    if (mChat.find()) cfg.alert.chat = Boolean.parseBoolean(mChat.group(1));
                }
            }
        } catch (Exception ignored) {}
        return cfg;
    }

    private static void parseSection(String text, String sectionName, java.util.function.Consumer<Boolean> setter) {
        int idx = text.indexOf("\"" + sectionName + "\"");
        if (idx != -1) {
            int start = text.indexOf('{', idx);
            int end = text.indexOf('}', start);
            if (start != -1 && end != -1) {
                String sec = text.substring(start, end + 1);
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"enabled\"\\s*:\\s*(true|false)").matcher(sec);
                if (m.find()) {
                    setter.accept(Boolean.parseBoolean(m.group(1)));
                }
            }
        }
    }

    public static synchronized void save(Path configDir, Config config) {
        Path file = configDir.resolve("antirat.json");
        try {
            Files.createDirectories(configDir);
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            sb.append("  \"enabled\": ").append(config.enabled).append(",\n");
            sb.append("  \"whitelistModIds\": [\n");
            for (int i = 0; i < config.whitelistModIds.size(); i++) {
                sb.append("    \"").append(config.whitelistModIds.get(i)).append("\"");
                if (i < config.whitelistModIds.size() - 1) sb.append(",");
                sb.append("\n");
            }
            sb.append("  ],\n");
            sb.append("  \"panicOnThreat\": ").append(config.panicOnThreat).append(",\n");
            sb.append("  \"scanner\": {\n    \"enabled\": ").append(config.scanner.enabled).append("\n  },\n");
            sb.append("  \"egressFilter\": {\n    \"enabled\": ").append(config.egressFilter.enabled).append("\n  },\n");
            sb.append("  \"quarantine\": {\n    \"enabled\": ").append(config.quarantine.enabled).append("\n  },\n");
            sb.append("  \"filesystemGuard\": {\n    \"enabled\": ").append(config.filesystemGuard.enabled).append("\n  },\n");
            sb.append("  \"processSandbox\": {\n    \"enabled\": ").append(config.processSandbox.enabled).append("\n  },\n");
            sb.append("  \"alert\": {\n    \"title\": ").append(config.alert.title).append(",\n    \"chat\": ").append(config.alert.chat).append("\n  },\n");
            sb.append("  \"log\": {\n    \"enabled\": ").append(config.log.enabled).append("\n  },\n");
            sb.append("  \"debug\": ").append(config.debug).append("\n");
            sb.append("}\n");
            Files.writeString(file, sb.toString());
        } catch (IOException ignored) {}
    }

    public boolean isWhitelisted(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            return false;
        }
        String clean = identifier.toLowerCase(java.util.Locale.ROOT).trim();
        if (CallerResolver.DEFAULT_HARDCODED_WHITELIST.contains(clean)) {
            return true;
        }
        if (whitelistModIds != null) {
            for (String entry : whitelistModIds) {
                if (entry == null) continue;
                String lowerEntry = entry.toLowerCase(java.util.Locale.ROOT).trim();
                if (clean.equals(lowerEntry) || clean.startsWith(lowerEntry) || lowerEntry.startsWith(clean)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static synchronized void addWhitelist(Path configDir, String modId) {
        if (modId == null || modId.isBlank()) {
            return;
        }
        Config config = load(configDir);
        if (!config.isWhitelisted(modId)) {
            config.whitelistModIds.add(modId);
            save(configDir, config);
        }
    }
}
