package com.ebremer.lws.server.http;

import java.io.IOException;
import java.util.Set;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * Cross-Origin Resource Sharing for the LWS HTTP API (finding M7).
 *
 * <p>The server had none: not one {@code Access-Control-*} header anywhere. Because an
 * {@code Authorization} header makes every authenticated request non-simple, a browser sends a
 * preflight {@code OPTIONS} first — which arrived carrying no credentials, was answered with
 * {@code Allow:} and (once the OPTIONS handler stopped being an existence oracle) frequently a
 * {@code 401}, and never with an {@code Access-Control-Allow-Origin}. So no browser application on
 * another origin could read anything here, and {@code acl:origin}, which this server's WAC engine
 * implements, was unreachable because no cross-origin request ever completed. For a storage whose
 * entire client story is browser apps that is the difference between a usable API and an unusable
 * one.
 *
 * <p><b>Off unless configured.</b> {@code lws.cors.allowed-origins} is empty by default and this
 * filter is not installed at all when it is.
 *
 * <p><b>No {@code Access-Control-Allow-Credentials}, ever.</b> The API authenticates with a bearer
 * or DPoP token in a header, which a cross-origin script must supply for itself; it never relies on
 * an ambient cookie. Never sending the header means a page on an allowed origin can only reach this
 * storage with a token it already holds, and means the management console's session cookie — which
 * {@code JettyLauncher} hardens with {@code SameSite=Strict} — cannot be borrowed by an allowed
 * origin either. The console tree is skipped outright as well; see {@link #isConsolePath}.
 *
 * <p><b>A preflight is answered here and goes no further.</b> It carries no credentials by
 * definition, so letting it reach the resource servlet would have it answered {@code 401} or
 * {@code 404} and the browser would block the real request that followed. The answer is a fixed
 * set of methods and headers, not one derived from the target: a preflight that reported what a
 * particular path supports would be the existence oracle {@code handleOptions} was rewritten to
 * close, reachable without credentials.
 *
 * @author Erich Bremer
 */
public final class CorsFilter implements Filter {

    /**
     * The request headers a cross-origin client may send, derived from what this server reads rather
     * than copied from a specification. {@code Accept}, {@code Content-Type} and {@code Content-Length}
     * are CORS-safelisted only for a narrow set of values, so they are listed too.
     */
    private static final String ALLOWED_HEADERS = String.join(", ",
            "Accept", "Authorization", "Content-Type", "Content-Digest", "DPoP", "Depth",
            "If-Match", "If-Modified-Since", "If-None-Match", "Link", "LWS-Purpose", "Prefer",
            "Range", "Slug", "Want-Content-Digest", "Want-Repr-Digest");

    /**
     * The response headers a cross-origin script may read. Only {@code Cache-Control},
     * {@code Content-Language}, {@code Content-Length}, {@code Content-Type}, {@code Expires},
     * {@code Last-Modified} and {@code Pragma} are readable without being named here — which leaves
     * out every header this protocol carries meaning in. {@code ETag} is the one a conditional write
     * depends on; {@code Location} the one a POST's result depends on; {@code WWW-Authenticate} and
     * {@code DPoP-Nonce} are how a client learns how to authenticate at all (RFC 9449 §8's nonce
     * challenge is unusable from a browser without it).
     */
    private static final String EXPOSED_HEADERS = String.join(", ",
            "Accept-Patch", "Accept-Post", "Accept-Ranges", "Allow", "Content-Digest",
            "Content-Range", "DPoP-Nonce", "ETag", "Link", "Location", "Preference-Applied",
            "Repr-Digest", "Vary", "Want-Content-Digest", "WWW-Authenticate");

    /** Every method any LWS servlet implements. Fixed, so a preflight discloses nothing. */
    private static final String ALLOWED_METHODS = "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE";

    private final Set<String> allowedOrigins; // lower-cased; empty when anyOrigin
    private final boolean anyOrigin;
    private final String maxAge;

    public CorsFilter(Set<String> allowedOrigins, boolean anyOrigin, long maxAgeSeconds) {
        this.allowedOrigins = Set.copyOf(allowedOrigins);
        this.anyOrigin = anyOrigin;
        this.maxAge = Long.toString(maxAgeSeconds);
    }

    /** The filter for a configuration, or {@code null} when no origin is allowed and it would do nothing. */
    public static CorsFilter forConfig(LwsConfiguration config) {
        if (!config.corsEnabled()) {
            return null;
        }
        return new CorsFilter(config.corsAllowedOrigins(), config.corsAllowsAnyOrigin(),
                config.corsMaxAgeSeconds());
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        String origin = request.getHeader("Origin");

        if (origin == null || isConsolePath(request.getRequestURI())) {
            chain.doFilter(req, res);
            return;
        }
        // Always, whether the origin is allowed or not, and before any early return: the response
        // differs by Origin, so a shared cache that did not key on it could serve an allowed
        // origin's headers to a refused one.
        HttpSupport.vary(response, "Origin");

        String allowOrigin = allowedOrigin(origin);
        if (allowOrigin == null) {
            // A refused origin gets the ordinary response with no CORS headers, which the browser
            // then blocks — rather than a 403, which would tell a page it had been singled out and
            // would break the many legitimate non-browser clients that send an Origin.
            chain.doFilter(req, res);
            return;
        }
        response.setHeader("Access-Control-Allow-Origin", allowOrigin);

        if (isPreflight(request)) {
            response.setHeader("Access-Control-Allow-Methods", ALLOWED_METHODS);
            response.setHeader("Access-Control-Allow-Headers", ALLOWED_HEADERS);
            response.setHeader("Access-Control-Max-Age", maxAge);
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return; // answered here; see the class javadoc
        }
        response.setHeader("Access-Control-Expose-Headers", EXPOSED_HEADERS);
        chain.doFilter(req, res);
    }

    /**
     * The value to echo in {@code Access-Control-Allow-Origin}, or {@code null} to refuse.
     *
     * <p>{@code Origin: null} is refused even under {@code *}. It is what a sandboxed iframe, a
     * {@code data:} document and a redirected cross-origin request send, and it is not an origin any
     * operator can have meant to allow.
     */
    private String allowedOrigin(String origin) {
        String o = origin.trim();
        if (o.isEmpty() || o.equalsIgnoreCase("null")) {
            return null;
        }
        if (anyOrigin) {
            // The literal `*`, not the echoed origin: with credentials never sent, the wildcard is
            // spec-legal and it lets a shared cache hold one entry instead of one per origin.
            return "*";
        }
        return allowedOrigins.contains(LwsConfiguration.normalizeOrigin(o)) ? o : null;
    }

    /** A CORS preflight: {@code OPTIONS} carrying the method the browser intends to use. */
    private static boolean isPreflight(HttpServletRequest request) {
        return request.getMethod().equalsIgnoreCase("OPTIONS")
                && request.getHeader("Access-Control-Request-Method") != null;
    }

    /**
     * The management console and the login callback, which CORS never applies to.
     *
     * <p>Defence in depth rather than the only defence: the console authenticates with a session
     * cookie, and no {@code Access-Control-Allow-Credentials} is ever sent, so a cross-origin fetch
     * of these paths is anonymous and gets an unauthenticated page whatever this does. Skipping them
     * means that stays true even if the credentials decision is ever revisited.
     */
    private static boolean isConsolePath(String uri) {
        return uri != null && (uri.equals(LwsConfiguration.UI_PREFIX)
                || uri.startsWith(LwsConfiguration.UI_PREFIX + "/")
                || uri.equals(LwsConfiguration.CALLBACK_PATH)
                || uri.startsWith(LwsConfiguration.CALLBACK_PATH + "/"));
    }
}
