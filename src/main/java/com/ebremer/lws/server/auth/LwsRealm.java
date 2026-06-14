package com.ebremer.lws.server.auth;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Shiro realm for LWS principals. Authentication is trivial (the token is pre-validated);
 * authorization grants the {@code owner} role and a {@code storage:control} permission to
 * configured storage owners, which the UI and any Shiro-based checks can consult.
 *
 * @author Erich Bremer
 */
public final class LwsRealm extends AuthorizingRealm {

    private final LwsConfiguration config;

    public LwsRealm(LwsConfiguration config) {
        this.config = config;
        setName("lws");
        setAuthenticationTokenClass(LwsAuthenticationToken.class);
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof LwsAuthenticationToken;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
        LwsPrincipal principal = ((LwsAuthenticationToken) token).lwsPrincipal();
        if (principal == null || principal.webId() == null) {
            throw new AuthenticationException("Missing subject");
        }
        return new SimpleAuthenticationInfo(principal, principal, getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        Object primary = principals.getPrimaryPrincipal();
        if (primary instanceof LwsPrincipal p) {
            info.addRole("authenticated");
            if (config.ownerWebIds().contains(p.webId())) {
                info.addRole("owner");
                info.addStringPermission("storage:control");
            }
        }
        return info;
    }
}
