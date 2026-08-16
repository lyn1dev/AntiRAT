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

    public static ThreatHandler getThreatHandler() {
        return threatHandler;
    }

    @Override
    public void onInitializeClient() {
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
        if (config.debug) {
            logger.log("AntiRAT initialized, game version " + loader.getRawGameVersion());
        }
    }
}
