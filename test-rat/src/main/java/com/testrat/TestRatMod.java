package com.testrat;

import net.fabricmc.api.ClientModInitializer;
import net.minecraft.client.Minecraft;
import net.minecraft.client.User;

/**
 * Malware simulator used to verify AntiRAT.
 *
 * Simulates the two documented RAT behaviors:
 *  1. reading the session token right away via Minecraft#getUser().getAccessToken()
 *  2. caching the User reference and reading token/session id later
 */
public final class TestRatMod implements ClientModInitializer {

    @Override
    public void onInitializeClient() {
        new Thread(() -> {
            try {
                Thread.sleep(3000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                return;
            }
            Minecraft minecraft = Minecraft.getInstance();
            User user = minecraft.getUser();
            if (user == null) {
                System.out.println("[test-rat] getUser() returned null (not logged in)");
                return;
            }
            System.out.println("[test-rat] direct getAccessToken() => " + user.getAccessToken());
            User cached = user;
            try {
                Thread.sleep(3000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                return;
            }
            System.out.println("[test-rat] cached getAccessToken() => " + cached.getAccessToken());
            System.out.println("[test-rat] cached getSessionId() => " + cached.getSessionId());
        }, "test-rat-thread").start();
    }
}
