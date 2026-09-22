package com.ebremer.lws.server.http;

import java.io.IOException;
import java.time.Clock;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.StorageDescriptionService;

/**
 * Serves the storage description at {@code <system-prefix>/storage-description}.
 *
 * <p>The description's canonical address is the storage URI — the root container's URI, answered
 * with the description unless the client asks for a container representation — and every resource
 * links there with {@code rel="https://www.w3.org/ns/lws#storage"}. This address is kept because
 * clients learned it when resources linked here with {@code lws:storageDescription}; it answers
 * with the description whatever {@code Accept} says. The rendering is shared with the storage URI
 * through {@link StorageDescriptionResponder}.
 *
 * @author Erich Bremer
 */
public final class StorageDescriptionServlet extends HttpServlet {

    private final transient StorageDescriptionResponder responder;

    public StorageDescriptionServlet(StorageDescriptionService descriptions, LwsConfiguration config, Clock clock) {
        this(new StorageDescriptionResponder(descriptions, config, clock.instant()));
    }

    public StorageDescriptionServlet(StorageDescriptionResponder responder) {
        this.responder = responder;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String method = req.getMethod();
        if (method.equals("OPTIONS")) {
            resp.setHeader("Allow", "GET, HEAD, OPTIONS");
            resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }
        if (!method.equals("GET") && !method.equals("HEAD")) {
            resp.setHeader("Allow", "GET, HEAD, OPTIONS");
            resp.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }
        responder.serve(req, resp, method.equals("GET"));
    }
}
