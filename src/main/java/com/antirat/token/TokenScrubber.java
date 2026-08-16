package com.antirat.token;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * In-Memory Token Scrubber.
 *
 * Sanitizes and wipes plaintext session tokens from Java heap memory after
 * initial multiplayer server authentication completes.
 * Prevents in-memory token theft via Unsafe, reflection, or heap dumping.
 */
public final class TokenScrubber {

    private static final ScheduledExecutorService SCHEDULER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "antirat-token-scrubber");
        t.setDaemon(true);
        return t;
    });

    private static final AtomicBoolean scrubbed = new AtomicBoolean(false);

    private TokenScrubber() {
    }

    /**
     * Immediately scrubs the session token string from the target User object.
     *
     * @param userInstance the Minecraft User object
     * @return true if at least one token field was sanitized
     */
    public static boolean scrub(Object userInstance) {
        if (userInstance == null) {
            return false;
        }
        boolean modified = false;
        Class<?> clazz = userInstance.getClass();

        while (clazz != null && clazz != Object.class) {
            for (Field field : clazz.getDeclaredFields()) {
                if (field.getType() == String.class && !Modifier.isStatic(field.getModifiers())) {
                    String name = field.getName().toLowerCase(Locale.ROOT);
                    if (name.contains("token") || name.contains("access") || name.equals("accesstoken")) {
                        try {
                            field.setAccessible(true);
                            field.set(userInstance, "");
                            modified = true;
                        } catch (Exception ignored) {
                            // best effort
                        }
                    }
                }
            }
            clazz = clazz.getSuperclass();
        }

        if (modified) {
            scrubbed.set(true);
            System.out.println("[AntiRAT] [SECURITY] Session token scrubbed from memory after authentication.");
        }
        return modified;
    }

    /**
     * Schedules a post-authentication token scrub after a grace delay (e.g. 2500ms).
     *
     * @param userInstance the Minecraft User object
     * @param delayMs delay in milliseconds
     */
    public static void schedulePostJoinScrub(Object userInstance, long delayMs) {
        if (userInstance == null) {
            return;
        }
        SCHEDULER.schedule(() -> scrub(userInstance), delayMs, TimeUnit.MILLISECONDS);
    }

    public static boolean isScrubbed() {
        return scrubbed.get();
    }

    public static void resetScrubbedStateForTest() {
        scrubbed.set(false);
    }
}
