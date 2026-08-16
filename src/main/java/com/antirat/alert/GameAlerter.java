package com.antirat.alert;

import com.antirat.core.Alerter;
import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.network.chat.Component;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * UI adapter. Security warnings are announced to the console immediately,
 * and queued for in-game chat once the player has entered a world.
 */
public final class GameAlerter implements Alerter {

    private final List<AlertMessage> pending = new ArrayList<AlertMessage>();
    private volatile ScheduledExecutorService poller;

    @Override
    public void alert(AlertMessage message) {
        System.out.println("[AntiRAT] " + message.chat());
        synchronized (pending) {
            pending.add(message);
        }
        ensurePoller();
    }

    private void ensurePoller() {
        if (poller != null) {
            return;
        }
        synchronized (this) {
            if (poller != null) {
                return;
            }
            ScheduledExecutorService service = Executors.newSingleThreadScheduledExecutor(runnable -> {
                Thread thread = new Thread(runnable, "antirat-alerter");
                thread.setDaemon(true);
                return thread;
            });
            poller = service;
            service.scheduleWithFixedDelay(this::poll, 500L, 500L, TimeUnit.MILLISECONDS);
        }
    }

    private void poll() {
        try {
            Minecraft minecraft = Minecraft.getInstance();
            if (minecraft == null) {
                return;
            }
            minecraft.execute(() -> {
                if (minecraft.player == null) {
                    return; // not in a world yet - keep waiting
                }
                List<AlertMessage> batch;
                synchronized (pending) {
                    if (pending.isEmpty()) {
                        return;
                    }
                    batch = new ArrayList<AlertMessage>(pending);
                    pending.clear();
                }
                announce(minecraft, batch);
                stopPoller();
            });
        } catch (Throwable ignored) {
            // never let the poller break the game
        }
    }

    private void announce(Minecraft minecraft, List<AlertMessage> batch) {
        AlertMessage first = batch.get(0);
        if (first.showChat()) {
            if (batch.size() == 1) {
                sendChat(minecraft, first.chat());
            } else {
                sendChat(minecraft, first.chat() + ", plus " + (batch.size() - 1)
                        + " other mod(s) were intercepted (see logs/antirat.log)");
            }
        }
    }

    private void sendChat(Minecraft minecraft, String text) {
        Component component = Component.literal("[AntiRAT] ").withStyle(ChatFormatting.RED)
                .append(Component.literal(text));
        try {
            Object chat = getChatComponent(minecraft.gui);
            if (chat != null) {
                chat.getClass().getMethod("addClientSystemMessage", Component.class).invoke(chat, component);
            }
        } catch (Throwable ignored) {
            // never break on chat delivery failure
        }
    }

    private static Object getChatComponent(Object gui) {
        if (gui == null) {
            return null;
        }
        try {
            // 26.2+: gui.hud.getChat()
            Field hudField = gui.getClass().getField("hud");
            Object hud = hudField.get(gui);
            if (hud != null) {
                Method getChat = hud.getClass().getMethod("getChat");
                return getChat.invoke(hud);
            }
        } catch (Throwable ignored) {
            // fallback to older layout
        }
        try {
            // 26.1.2 and earlier: gui.getChat()
            Method getChat = gui.getClass().getMethod("getChat");
            return getChat.invoke(gui);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private void stopPoller() {
        ScheduledExecutorService service = poller;
        poller = null;
        if (service != null) {
            service.shutdownNow();
        }
    }
}
