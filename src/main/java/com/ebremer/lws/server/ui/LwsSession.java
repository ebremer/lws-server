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

    /**
     * Attach an identity to this session, on a <em>new</em> container session.
     *
     * <p>Without the rotation the session that carries the identity is the same one the visitor
     * arrived with, so an attacker who can plant a session cookie before sign-in — a fixation
     * attack — holds a cookie that becomes authenticated the moment the victim signs in
     * (finding M30). All three sign-in routes (developer login, token login, OIDC) come through
     * here, so this is the single place it has to happen.
     */
    public void signIn(LwsPrincipal principal) {
        replaceSession();
        this.principal = principal;
        dirty();
    }

    /**
     * Sign out by destroying the session, not by blanking a field on it.
     *
     * <p>Clearing {@code principal} left the session, and with it Wicket's page store, alive: pages
     * rendered while signed in were still held, and their stateful component callbacks were still
     * invokable by their (guessable) URLs. {@code invalidateNow} takes the store with it.
     */
    public void signOut() {
        this.principal = null;
        invalidateNow();
    }
}
