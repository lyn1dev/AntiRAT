package fake.caller;

import com.antirat.core.ThreatHandler;

public class FakeCaller {
    public static boolean callGetAccessToken(ThreatHandler handler) {
        return handler.checkAndRespond(Object.class, "User#getAccessToken");
    }
}
