package com.antirat.mixin;

import com.antirat.AntiRatMod;
import com.antirat.core.ThreatHandler;
import net.minecraft.client.User;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

/**
 * Hooks the token accessors on {@link User}. These are the ONLY places the
 * session token is exposed by then official client API, so this is the single
 * interception point: it covers direct reads, cached {@code User} references
 * and reflection. Minecraft#getUser itself is deliberately NOT touched - it is
 * the standard way mods read the (non-secret) player name, so flagging it would
 * produce false positives on normal mods.
 * The {@code getSessionId} shortcut embeds the access token and is covered too.
 */
@Mixin(User.class)
public abstract class UserMixin {

    @Inject(method = "getAccessToken", at = @At("RETURN"), cancellable = true)
    private void antirat$onGetAccessToken(CallbackInfoReturnable<String> cir) {
        ThreatHandler handler = AntiRatMod.getThreatHandler();
        if (handler == null) {
            return;
        }
        if (handler.checkAndRespond(User.class, "User#getAccessToken")) {
            cir.setReturnValue("");
        }
    }

    @Inject(method = "getSessionId", at = @At("RETURN"), cancellable = true)
    private void antirat$onGetSessionId(CallbackInfoReturnable<String> cir) {
        ThreatHandler handler = AntiRatMod.getThreatHandler();
        if (handler == null) {
            return;
        }
        if (handler.checkAndRespond(User.class, "User#getSessionId")) {
            cir.setReturnValue("");
        }
    }
}
