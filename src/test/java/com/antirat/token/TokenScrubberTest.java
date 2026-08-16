package com.antirat.token;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenScrubberTest {

    public static class DummyMinecraftUser {
        private final String name = "TestPlayer";
        private final String uuid = "00000000-0000-0000-0000-000000000000";
        private String accessToken = "secret-session-token-xyz-123456";

        public String getAccessToken() {
            return accessToken;
        }
    }

    @BeforeEach
    void setUp() {
        TokenScrubber.resetScrubbedStateForTest();
    }

    @Test
    void immediateScrubClearsAccessTokenField() {
        DummyMinecraftUser user = new DummyMinecraftUser();
        assertEquals("secret-session-token-xyz-123456", user.getAccessToken());

        boolean result = TokenScrubber.scrub(user);
        assertTrue(result);
        assertEquals("", user.getAccessToken());
        assertTrue(TokenScrubber.isScrubbed());
    }

    @Test
    void scheduledScrubExecutesAfterDelay() throws Exception {
        DummyMinecraftUser user = new DummyMinecraftUser();
        TokenScrubber.schedulePostJoinScrub(user, 50);

        // Immediate check: token still present during initial server join handshake
        assertEquals("secret-session-token-xyz-123456", user.getAccessToken());

        // Wait for scheduler grace period
        Thread.sleep(150);

        assertEquals("", user.getAccessToken());
        assertTrue(TokenScrubber.isScrubbed());
    }

    @Test
    void nullUserHandledSafely() {
        assertFalse(TokenScrubber.scrub(null));
        TokenScrubber.schedulePostJoinScrub(null, 100);
    }
}
