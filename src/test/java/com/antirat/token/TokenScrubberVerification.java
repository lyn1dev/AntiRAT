package com.antirat.token;

public class TokenScrubberVerification {

    public static class DummyMinecraftUser {
        private final String name = "TestPlayer";
        private final String uuid = "00000000-0000-0000-0000-000000000000";
        private String accessToken = "secret-session-token-xyz-123456";

        public String getAccessToken() {
            return accessToken;
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("[TokenScrubberVerification] Running Rank 2 In-Memory Token Scrubber tests...");
        TokenScrubber.resetScrubbedStateForTest();

        testImmediateScrub();
        testScheduledPostAuthScrub();

        System.out.println("[TokenScrubberVerification] ALL TOKEN SCRUBBER TESTS PASSED! (2/2)");
    }

    private static void testImmediateScrub() {
        DummyMinecraftUser user = new DummyMinecraftUser();
        if (!user.getAccessToken().equals("secret-session-token-xyz-123456")) {
            throw new AssertionError("Initial token mismatch");
        }

        boolean scrubbed = TokenScrubber.scrub(user);
        if (!scrubbed || !user.getAccessToken().isEmpty() || !TokenScrubber.isScrubbed()) {
            throw new AssertionError("Failed to scrub access token from memory");
        }
        System.out.println("  ✓ Immediate reflection-based token wipe confirmed in heap memory");
    }

    private static void testScheduledPostAuthScrub() throws Exception {
        TokenScrubber.resetScrubbedStateForTest();
        DummyMinecraftUser user = new DummyMinecraftUser();

        TokenScrubber.schedulePostJoinScrub(user, 50);

        if (!user.getAccessToken().equals("secret-session-token-xyz-123456")) {
            throw new AssertionError("Token was cleared prematurely before handshake");
        }

        Thread.sleep(150);

        if (!user.getAccessToken().isEmpty() || !TokenScrubber.isScrubbed()) {
            throw new AssertionError("Scheduled post-auth token wipe failed");
        }
        System.out.println("  ✓ Scheduled post-auth grace period and async heap wipe confirmed");
    }
}
