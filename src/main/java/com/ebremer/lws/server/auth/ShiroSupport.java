package com.ebremer.lws.server.auth;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * Builds and installs the Apache Shiro {@link SecurityManager} used for LWS authentication.
 *
 * @author Erich Bremer
 */
public final class ShiroSupport {

    private ShiroSupport() {
    }

    public static SecurityManager createSecurityManager(LwsConfiguration config) {
        DefaultSecurityManager sm = new DefaultSecurityManager(new LwsRealm(config));
        SecurityUtils.setSecurityManager(sm);
        return sm;
    }
}
