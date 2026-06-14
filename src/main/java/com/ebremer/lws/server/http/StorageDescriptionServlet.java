package com.ebremer.lws.server.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.jena.rdf.model.Model;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.Etags;
import com.ebremer.lws.server.core.StorageDescriptionService;
import com.ebremer.lws.server.rdf.RdfFormats;
import com.ebremer.lws.server.rdf.RdfIO;

/**
 * Serves the storage description resource ({@code lws:StorageDescription}) with content
 * negotiation. Clients discover the storage's services (notifications) and capabilities here;
 * resources link to it via the {@code lws:storageDescription} Link relation.
 *
 * @author Erich Bremer
 */
public final class StorageDescriptionServlet extends HttpServlet {

    private final transient StorageDescriptionService descriptions;
    private final transient LwsConfiguration config;
    private final Instant lastModified;

    public StorageDescriptionServlet(StorageDescriptionService descriptions, LwsConfiguration config, Clock clock) {
        this.descriptions = descriptions;
        this.config = config;
        this.lastModified = clock.instant();
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
        Model model = descriptions.buildModel();
        String etag = "\"" + Etags.forModel(model) + "\"";
        resp.setHeader("ETag", etag);
        resp.setHeader("Last-Modified", HttpSupport.httpDate(lastModified));
        resp.setHeader("Vary", "Accept");
        resp.addHeader("Link", "<" + config.storageDescriptionIri() + ">; rel=\""
                + HttpSupport.REL_STORAGE_DESCRIPTION + "\"");

        String inm = req.getHeader("If-None-Match");
        if (inm != null && (inm.trim().equals("*") || inm.contains(etag))) {
            resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }
        if (HttpSupport.notModifiedSince(req, lastModified)) {
            resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }

        String accept = req.getHeader("Accept");
        byte[] body;
        String contentType;
        if (RdfFormats.prefersRdf(accept)) {
            RdfFormats.Entry fmt = RdfFormats.negotiate(accept);
            body = RdfIO.write(model, fmt.writeFormat());
            contentType = fmt.mediaType();
        } else {
            // Canonical representation: application/lws+json (echoing the requested JSON-family type).
            body = descriptions.buildJson().getBytes(StandardCharsets.UTF_8);
            contentType = RdfFormats.jsonFamilyContentType(accept);
        }
        resp.setContentType(contentType + ";charset=utf-8");
        resp.setContentLength(body.length);
        if (method.equals("GET")) {
            resp.getOutputStream().write(body);
        }
    }
}
