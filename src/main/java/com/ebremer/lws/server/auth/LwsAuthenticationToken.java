package com.ebremer.lws.server.auth;

import org.apache.shiro.authc.AuthenticationToken;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * A Shiro {@link AuthenticationToken} carrying an already-validated {@link LwsPrincipal}. The
 * heavy lifting (signature/issuer/trust checks) happens in {@link LwsOpenIdValidator} before
 * this token is presented, so the realm simply accepts it.
 *
 * @author Erich Bremer
 */
public final class LwsAuthenticationToken implements AuthenticationToken {

    private final LwsPrincipal principal;

    public LwsAuthenticationToken(LwsPrincipal principal) {
        this.principal = principal;
    }

    public LwsPrincipal lwsPrincipal() {
        return principal;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public Object getCredentials() {
        return principal;
    }
}
