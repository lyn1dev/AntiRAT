package com.antirat.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Configuration persisted to {@code config/antirat.json}. */
public final class Config {

    @SerializedName("enabled")
    public boolean enabled = true;

    @SerializedName("whitelistModIds")
    public List<String> whitelistModIds = new ArrayList<>();

    @SerializedName("panicOnThreat")
    public boolean panicOnThreat = true;

    @SerializedName("scanner")
    public Scanner scanner = new Scanner();

    @SerializedName("quarantine")
    public Quarantine quarantine = new Quarantine();

    @SerializedName("alert")
    public Alert alert = new Alert();

    @SerializedName("log")
    public Log log = new Log();

    @SerializedName("debug")
    public boolean debug = false;

    public static final class Scanner {
        @SerializedName("enabled")
        public boolean enabled = true;
    }

    public static final class Quarantine {
        @SerializedName("enabled")
        public boolean enabled = true;
    }

    public static final class Alert {
        @SerializedName("title")
        public boolean title = true;

        @SerializedName("chat")
        public boolean chat = true;
    }

    public static final class Log {
        @SerializedName("enabled")
        public boolean enabled = true;
    }

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public static Config load(Path configDir) {
        Path file = configDir.resolve("antirat.json");
        if (!Files.exists(file)) {
            try {
                Files.createDirectories(configDir);
                Files.writeString(file, GSON.toJson(new Config()));
            } catch (IOException ignored) {
                // best effort; defaults still apply
            }
            return new Config();
        }
        try {
            Config parsed = GSON.fromJson(Files.readString(file), Config.class);
            if (parsed != null) {
                if (parsed.whitelistModIds == null) {
                    parsed.whitelistModIds = new ArrayList<>();
                }
                if (parsed.scanner == null) {
                    parsed.scanner = new Scanner();
                }
                if (parsed.quarantine == null) {
                    parsed.quarantine = new Quarantine();
                }
                if (parsed.alert == null) {
                    parsed.alert = new Alert();
                }
                if (parsed.log == null) {
                    parsed.log = new Log();
                }
                return parsed;
            }
        } catch (Exception ignored) {
            // fall through to defaults
        }
        return new Config();
    }
}
