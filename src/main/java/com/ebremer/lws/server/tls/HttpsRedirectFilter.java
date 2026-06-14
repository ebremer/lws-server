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
 * shared context) redirects plaintext requests to HTTPS with {@code 301}, leaving the ACME HTTP-01
 * challenge path untouched so a certificate can still be (re)provisioned over port 80. Requests that
 * already arrived over TLS pass straight through.
 *
 * @author Erich Bremer
 */
public final class HttpsRedirectFilter implements Filter {

    private final int httpsPort;

    public HttpsRedirectFilter(int httpsPort) {
        this.httpsPort = httpsPort;
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
        String portPart = httpsPort == 443 ? "" : ":" + httpsPort;
        String query = request.getQueryString() == null ? "" : "?" + request.getQueryString();
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
        response.setHeader("Location", "https://" + request.getServerName() + portPart
                + request.getRequestURI() + query);
    }
}
