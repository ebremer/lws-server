package com.ebremer.lws.server.tls;

import java.io.IOException;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * Emits {@code Strict-Transport-Security} on responses that actually went out over TLS.
 *
 * <p>The header used to be set in exactly one place: on the plaintext {@code 308} that
 * {@link HttpsRedirectFilter} sends. RFC 6797 &sect;8.1 requires a user agent to <em>ignore</em> an
 * STS header received over a non-secure transport, so that one was inert — the server advertised
 * HSTS and no browser ever recorded it. Worse, it was only installed at all under
 * {@code lws.tls.enabled}, which the Spring Boot bootstrap does not implement; the deployment the
 * README calls the default (TLS terminated at a reverse proxy, {@code lws.behind-proxy=true}) emitted
 * no HSTS on any response at all.
 *
 * <p>So it moves here, onto the response, in both bootstraps. {@code isSecure()} is the test, and it
 * is the right one for both: Jetty answers it from the connector when the server terminates TLS, and
 * from the {@code X-Forwarded-Proto} / {@code Forwarded} headers that {@code ForwardedRequestCustomizer}
 * consumes when a trusted proxy does — the same signal
 * {@code SessionHandler.setSecureRequestOnly} is already given.
 *
 * <p>{@code includeSubDomains} and {@code preload} are deliberately absent. Both commit names other
 * than this one — a subdomain that is not ready for HTTPS, or an entry in a browser-shipped list that
 * takes months to leave — and neither is a decision a storage server should make on an operator's
 * behalf. An operator who wants them can add them at the proxy.
 *
 * @author Erich Bremer
 */
public final class HstsFilter implements Filter {

    private final String headerValue;

    /**
     * @param maxAgeSeconds the HSTS lifetime; {@code <= 0} disables the header entirely
     */
    public HstsFilter(long maxAgeSeconds) {
        this.headerValue = maxAgeSeconds > 0 ? "max-age=" + maxAgeSeconds : null;
    }

    /**
     * The filter for a configuration, or {@code null} when it would do nothing: HSTS is disabled, or
     * the storage's public base URI is not {@code https}, in which case telling a browser to use
     * HTTPS for this host would make the storage unreachable.
     */
    public static HstsFilter forConfig(LwsConfiguration config) {
        if (config.hstsMaxAgeSeconds() <= 0 || !config.baseUri().startsWith("https://")) {
            return null;
        }
        return new HstsFilter(config.hstsMaxAgeSeconds());
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        if (headerValue != null && req instanceof HttpServletRequest request && request.isSecure()
                && res instanceof HttpServletResponse response) {
            response.setHeader("Strict-Transport-Security", headerValue);
        }
        chain.doFilter(req, res);
    }
}
