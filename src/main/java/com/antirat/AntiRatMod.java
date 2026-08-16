package com.antirat;

import com.antirat.alert.GameAlerter;
import com.antirat.core.CallerResolver;
import com.antirat.core.Config;
import com.antirat.core.FabricModIndex;
import com.antirat.core.QuarantineManager;
import com.antirat.core.RatLogger;
import com.antirat.core.ThreatHandler;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.loader.api.FabricLoader;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public final class AntiRatMod implements ClientModInitializer {

    private static volatile ThreatHandler threatHandler;

    /**
     * Retrieves the global ThreatHandler instance. If called early (e.g. during preLaunch
     * or early mixins), it self-initializes immediately to prevent null bypasses.
     */
    public static ThreatHandler getThreatHandler() {
        ThreatHandler local = threatHandler;
        if (local == null) {
            synchronized (AntiRatMod.class) {
                if (threatHandler == null) {
                    initEarly();
                }
                local = threatHandler;
            }
        }
        return local;
    }

    /**
     * Initializes core threat protection early in the JVM lifecycle.
     */
    public static synchronized void initEarly() {
        if (threatHandler != null) {
            return;
        }
        FabricLoader loader = FabricLoader.getInstance();
        Config config = Config.load(loader.getConfigDir());
        RatLogger logger = new RatLogger(loader.getGameDir());
        CallerResolver resolver = new CallerResolver(new FabricModIndex(), config.whitelistModIds);
        QuarantineManager quarantineManager = new QuarantineManager(loader.getGameDir().resolve("mods"));
        Executor executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "antirat-worker");
            thread.setDaemon(true);
            return thread;
        });
        threatHandler = new ThreatHandler(config, resolver, quarantineManager, logger, new GameAlerter(), executor);
        com.antirat.core.FilesystemAccountGuard.install(config, threatHandler);
        com.antirat.core.ProcessExecutionSandbox.install(config, threatHandler);
        if (config.debug) {
            logger.log("AntiRAT core initialized early, game version " + loader.getRawGameVersion());
        }
    }

    @Override
    public void onInitializeClient() {
        initEarly();
    }
}
