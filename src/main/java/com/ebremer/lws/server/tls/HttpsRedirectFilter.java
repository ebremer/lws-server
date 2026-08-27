package com.ebremer.lws.server.tls;

import java.io.IOException;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * When TLS is terminated by the server itself, this filter (installed only on the HTTP connector's
 * shared context) redirects plaintext requests to HTTPS, leaving the ACME HTTP-01 challenge path
 * untouched so a certificate can still be (re)provisioned over port 80. Requests that already
 * arrived over TLS pass straight through.
 *
 * <p><b>It waits for the HTTPS connector (finding M28).</b> The filter went live with
 * {@code server.start()} while {@code enableTls} was still blocking on the whole ACME order — the
 * account registration, an HTTP-01 challenge per domain and the certificate download, minutes for
 * three domains, and longer when the order is failing. Every request arriving in that window was
 * answered with a <em>permanent</em> redirect to a port where nothing was listening. Permanent is
 * the problem: browsers and intermediaries cache a {@code 308} indefinitely, so a client that
 * arrived during provisioning could keep being sent to a dead port long after TLS came up.
 *
 * <p>Until the connector is up, the answer is {@code 503} with {@code Retry-After} — a status that is
 * not cached and says what is true. That includes {@code /app}: the management console runs on a
 * session cookie, and serving it in the clear on a server whose whole configuration says "terminate
 * TLS" is the downgrade this filter exists to prevent. An operator whose ACME order is failing reads
 * the log, which says so on every attempt; one who wants plaintext service meanwhile sets
 * {@code lws.tls.enabled=false}. The ACME challenge path is exempt, because it is how the outage
 * ends.
 *
 * <p>No {@code Strict-Transport-Security} here. It used to be set on the plaintext {@code 308}, where
 * RFC 6797 &sect;8.1 requires a user agent to ignore it; it now lives in {@link HstsFilter}, on the
 * secure responses where it takes effect.
 *
 * @author Erich Bremer
 */
public final class HttpsRedirectFilter implements Filter {

    /** How long a client is asked to wait while the HTTPS connector is still coming up. */
    private static final String RETRY_AFTER_SECONDS = "10";

    private final int httpsPort;
    private final String canonicalHost;
    private final java.util.function.BooleanSupplier httpsReady;

    /**
     * @param httpsReady whether the HTTPS connector is accepting connections; there is deliberately
     *                   no constructor without it, because a caller that forgot to wire the gate
     *                   would silently restore the cacheable-redirect-to-a-dead-port behaviour and
     *                   every test would still pass
     */
    public HttpsRedirectFilter(int httpsPort, String baseUri, java.util.function.BooleanSupplier httpsReady) {
        this.httpsPort = httpsPort;
        this.canonicalHost = hostOf(baseUri);
        this.httpsReady = httpsReady;
    }

    private static String hostOf(String baseUri) {
        try {
            String host = java.net.URI.create(baseUri).getHost();
            return host == null ? null : host.toLowerCase(java.util.Locale.ROOT);
        } catch (RuntimeException e) {
            return null;
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        if (request.isSecure() || request.getRequestURI().startsWith(AcmeChallengeServlet.PATH)) {
            chain.doFilter(req, res);
            return;
        }
        if (!httpsReady.getAsBoolean()) {
            // Not a redirect: there is nowhere to send them yet, and a permanent one would outlive
            // the window it was issued in. 503 is explicitly non-cacheable without an explicit
            // freshness header, so the client simply retries once the connector is up.
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.setHeader("Retry-After", RETRY_AFTER_SECONDS);
            return;
        }
        // The host is taken from the configured base URI, not from the request. getServerName()
        // is the client's Host header, so reflecting it turned this filter into an open redirect
        // that any client could aim anywhere simply by lying about Host.
        String host = canonicalHost != null ? canonicalHost : request.getServerName();
        String portPart = httpsPort == 443 ? "" : ":" + httpsPort;
        String query = request.getQueryString() == null ? "" : "?" + request.getQueryString();
        // 308, not 301: a 301 lets (and historically encouraged) a client rewrite POST to GET, so a
        // redirected write silently became a read. 308 preserves the method and the body.
        response.setStatus(308); // Permanent Redirect (RFC 9110); no constant for it in the Servlet API
        response.setHeader("Location", "https://" + host + portPart + request.getRequestURI() + query);
    }
}
