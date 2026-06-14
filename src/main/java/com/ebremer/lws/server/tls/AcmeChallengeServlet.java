package com.ebremer.lws.server.tls;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Serves the ACME HTTP-01 challenge response at {@code /.well-known/acme-challenge/<token>} (RFC 8555
 * §8.3): plain-text key authorization for a known token, {@code 404} otherwise. Mapped on the HTTP
 * connector so the ACME server can reach it over port 80 before any certificate exists.
 *
 * @author Erich Bremer
 */
public final class AcmeChallengeServlet extends HttpServlet {

    /** The path prefix this servlet is mounted at. */
    public static final String PATH = "/.well-known/acme-challenge/";

    private final transient AcmeChallengeStore challenges;

    public AcmeChallengeServlet(AcmeChallengeStore challenges) {
        this.challenges = challenges;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String token = req.getPathInfo(); // "/<token>" for the /*-mapped servlet
        if (token != null && token.startsWith("/")) {
            token = token.substring(1);
        }
        String keyAuthorization = token == null || token.isBlank() ? null : challenges.get(token);
        if (keyAuthorization == null) {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        // RFC 8555 §8.3: the response body is the key authorization, served as application/octet-stream.
        resp.setContentType("application/octet-stream");
        resp.getOutputStream().write(keyAuthorization.getBytes(StandardCharsets.US_ASCII));
    }
}
