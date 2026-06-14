package com.ebremer.lws.server.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.ebremer.lws.server.notifications.WebhookKeys;

/**
 * Publishes the server's webhook signing public key as a JWK Set so notification subscribers can
 * verify the HTTP Message Signatures on delivered notifications (the signature {@code keyid} is
 * the JWK thumbprint of this key).
 *
 * @author Erich Bremer
 */
public final class JwksServlet extends HttpServlet {

    private final transient WebhookKeys keys;

    public JwksServlet(WebhookKeys keys) {
        this.keys = keys;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (req.getMethod().equals("OPTIONS")) {
            resp.setHeader("Allow", "GET, HEAD, OPTIONS");
            resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }
        if (!req.getMethod().equals("GET") && !req.getMethod().equals("HEAD")) {
            resp.setHeader("Allow", "GET, HEAD, OPTIONS");
            resp.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }
        byte[] body = keys.publicJwkSetJson().getBytes(StandardCharsets.UTF_8);
        resp.setContentType("application/jwk-set+json");
        resp.setContentLength(body.length);
        resp.setHeader("Cache-Control", "public, max-age=3600");
        if (req.getMethod().equals("GET")) {
            resp.getOutputStream().write(body);
        }
    }
}
