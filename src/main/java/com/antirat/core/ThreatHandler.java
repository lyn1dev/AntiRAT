package com.antirat.core;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;

/**
 * Central decision point for the session-token guards.
 *
 * On the first hit from a given mod the handler logs, alerts and (if enabled)
 * asynchronously quarantines the mod's jar. Subsequent hits from the same mod
 * keep being neutralized but no longer re-alert or re-move files.
 */
public final class ThreatHandler {

    private final Config config;
    private final CallerResolver resolver;
    private final QuarantineManager quarantineManager;
    private final RatLogger logger;
    private final Alerter alerter;
    private final Executor executor;
    private final Set<String> handledMods = ConcurrentHashMap.newKeySet();
    private final Map<String, Integer> hitCounts = new ConcurrentHashMap<>();

    private final Runnable panicAction;

    public ThreatHandler(Config config, CallerResolver resolver, QuarantineManager quarantineManager,
                         RatLogger logger, Alerter alerter, Executor executor) {
        this(config, resolver, quarantineManager, logger, alerter, executor, () -> Runtime.getRuntime().halt(1));
    }

    public ThreatHandler(Config config, CallerResolver resolver, QuarantineManager quarantineManager,
                         RatLogger logger, Alerter alerter, Executor executor, Runnable panicAction) {
        this.config = config;
        this.resolver = resolver;
        this.quarantineManager = quarantineManager;
        this.logger = logger;
        this.alerter = alerter;
        this.executor = executor;
        this.panicAction = panicAction != null ? panicAction : () -> Runtime.getRuntime().halt(1);
    }

    /**
     * Checks whether the current call should be neutralized.
     *
     * @return true if the call is malicious and the caller must return a
     *         sanitized/empty value instead of the real token
     */
    public boolean checkAndRespond(Class<?> hookTarget, String accessPoint) {
        if (!config.enabled) {
            return false;
        }
        CallerResolver.Resolution resolution = resolver.resolveCaller(hookTarget, accessPoint);
        if (resolution.trust() != CallerResolver.Trust.SUSPICIOUS) {
            return false;
        }

        String modId = resolution.modId();
        int hits = hitCounts.merge(modId, 1, Integer::sum);
        boolean firstHit = handledMods.add(modId);
        String origin = resolution.origin();
        String fileName = fileNameOf(modId, origin);

        if (config.log.enabled) {
            StringBuilder message = new StringBuilder();
            message.append("SUSPICIOUS ").append(accessPoint)
                    .append(" by mod '").append(modId)
                    .append("' origin=").append(origin)
                    .append(" hits=").append(hits);
            for (StackTraceElement element : Thread.currentThread().getStackTrace()) {
                message.append(System.lineSeparator()).append("  at ").append(element);
            }
            logger.log(message.toString());
        }

        if (config.panicOnThreat) {
            StringBuilder panicAlert = new StringBuilder();
            panicAlert.append(System.lineSeparator())
                    .append("================================================================================").append(System.lineSeparator())
                    .append(" [AntiRAT] [CRITICAL THREAT DETECTED] SESSION THEFT ATTEMPT BLOCKED!           ").append(System.lineSeparator())
                    .append("================================================================================").append(System.lineSeparator())
                    .append(" Mod ID:       '").append(modId).append("' (").append(fileName).append(")").append(System.lineSeparator())
                    .append(" Access Point: ").append(accessPoint).append(System.lineSeparator())
                    .append(" Origin:       ").append(origin).append(System.lineSeparator())
                    .append(" Action:       Halting JVM process immediately to prevent data exfiltration.").append(System.lineSeparator())
                    .append("================================================================================").append(System.lineSeparator());
            System.err.println(panicAlert);

            // Execute emergency panic termination
            panicAction.run();
            return true;
        }

        if (firstHit) {
            String consoleAlert = "[AntiRAT] [ALERT] Mod '" + modId + "' (" + fileName + ") attempted to access session token via " + accessPoint + ". Returned empty value.";
            System.err.println(consoleAlert);
            if (config.alert.title || config.alert.chat) {
                alerter.alert(new Alerter.AlertMessage(
                        "AntiRAT: Session token access blocked",
                        "Mod '" + modId + "' (" + fileName + ") attempted to read your session token. An empty value was returned.",
                        "Mod '" + modId + "' (" + fileName + ") attempted to read your session token. An empty value was returned.",
                        config.alert.title,
                        config.alert.chat));
            }
        }

        if (firstHit && config.quarantine.enabled) {
            executor.execute(() -> {
                QuarantineManager.Outcome outcome = quarantineManager.quarantine(modId, origin);
                if (config.log.enabled) {
                    logger.log("QUARANTINE mod=" + modId + " result=" + outcome.result()
                            + " target=" + outcome.target()
                            + " detail=" + outcome.detail());
                }
            });
        }
        return true;
    }

    private static String fileNameOf(String modId, String origin) {
        if (origin == null || origin.isEmpty()) {
            return modId;
        }
        try {
            Path path = Path.of(origin);
            Path fileName = path.getFileName();
            return fileName == null ? modId : fileName.toString();
        } catch (Exception e) {
            return modId;
        }
    }
}
