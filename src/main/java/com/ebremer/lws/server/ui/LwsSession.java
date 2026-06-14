package com.ebremer.lws.server.ui;

import org.apache.wicket.Session;
import org.apache.wicket.protocol.http.WebSession;
import org.apache.wicket.request.Request;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Wicket session holding the UI's currently signed-in {@link LwsPrincipal} (or {@code null} for
 * anonymous). Management actions are performed in-process against the service layer as this
 * principal, so authorization (owner policy or WAC) is enforced server-side exactly as it is for
 * the HTTP API.
 *
 * @author Erich Bremer
 */
public final class LwsSession extends WebSession {

    private LwsPrincipal principal;

    public LwsSession(Request request) {
        super(request);
    }

    public static LwsSession get() {
        return (LwsSession) Session.get();
    }

    public LwsPrincipal getPrincipal() {
        return principal;
    }

    public boolean isSignedIn() {
        return principal != null;
    }

    public void signIn(LwsPrincipal principal) {
        this.principal = principal;
        dirty();
    }

    public void signOut() {
        this.principal = null;
        dirty();
    }
}
