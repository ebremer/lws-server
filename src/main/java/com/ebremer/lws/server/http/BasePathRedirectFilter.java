package com.ebremer.lws.server.http;

import java.io.IOException;
import java.net.URI;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * Puts the path of {@code lws.base-uri} back into the console's redirects.
 *
 * <p>A storage published under a path ({@code lws.base-uri=https://host/lws}) sits behind a proxy
 * that strips that path, so the server sees {@code /app/browse} where the browser asked for
 * {@code /lws/app/browse}. Wicket and pac4j build their redirects from the request they see, and
 * send the browser to {@code https://host/app/browse} — off the storage, and on a shared host into
 * whatever else lives there. The storage API never had the problem: every IRI it mints comes from
 * {@code lws.base-uri}.
 *
 * <p>A redirect is rewritten only when it stays on this origin and lands in the console's own trees
 * ({@code /app} and the OIDC {@code /callback}); anything else, such as the identity provider's
 * authorization endpoint, passes through unchanged. Not installed when the base URI has no path.
 *
 * @author Erich Bremer
 */
public final class BasePathRedirectFilter implements Filter {

    private final String baseUri;

    private BasePathRedirectFilter(String baseUri) {
        this.baseUri = baseUri;
    }

    /** The filter for this configuration, or {@code null} when the base URI has no path. */
    public static BasePathRedirectFilter forConfig(LwsConfiguration config) {
        String path = URI.create(config.baseUri()).getRawPath();
        return path == null || path.isEmpty() || path.equals("/") ? null : new BasePathRedirectFilter(config.baseUri());
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        chain.doFilter(req, new HttpServletResponseWrapper((HttpServletResponse) res) {
            @Override
            public void sendRedirect(String location) throws IOException {
                super.sendRedirect(rewrite(request, location));
            }

            @Override
            public void setHeader(String name, String value) {
                super.setHeader(name, isLocation(name) ? rewrite(request, value) : value);
            }

            @Override
            public void addHeader(String name, String value) {
                super.addHeader(name, isLocation(name) ? rewrite(request, value) : value);
            }
        });
    }

    private static boolean isLocation(String name) {
        return "Location".equalsIgnoreCase(name);
    }

    /** {@code location} under the base URI if it is a same-origin console address, else unchanged. */
    String rewrite(HttpServletRequest request, String location) {
        if (location == null) {
            return null;
        }
        URI target;
        try {
            target = URI.create(request.getRequestURL().toString()).resolve(location);
        } catch (IllegalArgumentException e) {
            return location;
        }
        URI base = URI.create(baseUri);
        String path = target.getRawPath();
        boolean sameOrigin = sameOrigin(target, URI.create(request.getRequestURL().toString()))
                || sameOrigin(target, base);
        if (!sameOrigin || path == null || !(isUnder(path, LwsConfiguration.UI_PREFIX)
                || isUnder(path, LwsConfiguration.CALLBACK_PATH))) {
            return location;
        }
        return baseUri + path
                + (target.getRawQuery() == null ? "" : "?" + target.getRawQuery())
                + (target.getRawFragment() == null ? "" : "#" + target.getRawFragment());
    }

    private static boolean sameOrigin(URI a, URI b) {
        return a.getScheme() != null && a.getScheme().equalsIgnoreCase(b.getScheme())
                && a.getRawAuthority() != null && a.getRawAuthority().equalsIgnoreCase(b.getRawAuthority());
    }

    private static boolean isUnder(String path, String prefix) {
        return path.equals(prefix) || path.startsWith(prefix + "/");
    }
}
