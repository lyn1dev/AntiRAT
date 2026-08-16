package fake.caller;

import com.antirat.core.CallerResolver;
import com.antirat.core.ThreatHandler;

public class FakeCaller {
    public static boolean callGetAccessToken(ThreatHandler handler) {
        return handler.checkAndRespond(Object.class, "User#getAccessToken");
    }

    public static CallerResolver.Resolution resolveThroughFakeMod(CallerResolver resolver) {
        return resolver.resolveCaller(Object.class, "fakeModPoint");
    }
}
