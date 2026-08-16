package com.antirat.core;

/** Callback used by the threat handler to surface alerts in the game UI. */
public interface Alerter {

    void alert(AlertMessage message);

    record AlertMessage(String title, String subtitle, String chat, boolean showTitle, boolean showChat) {
    }
}
