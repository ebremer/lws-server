package com.ebremer.lws.server.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
        // Negotiate first: the entity-tag names the representation that was selected, and Vary has
        // to be on the 304 as well as the 200 (RFC 9110 §8.8.1 and §15.4.5, finding M21).
        String accept = req.getHeader("Accept");
        boolean rdf = RdfFormats.prefersRdf(accept);
        RdfFormats.Entry fmt = rdf ? RdfFormats.negotiate(accept) : null;
        // The base tag is a hash of the canonical JSON, computed once at construction. It used to be
        // Etags.forModel over a model containing fresh blank nodes, so it differed on every call and
        // a conditional GET on discovery could never return 304 (finding M22). It is a valid
        // validator for the RDF rendering too, because that rendering is now derived from the same
        // JSON document rather than written out separately.
        String etag = Etags.qualify(descriptions.etagBase(),
                rdf ? fmt.variantToken() : RdfFormats.LWS_JSON_VARIANT);
        resp.setHeader("ETag", "\"" + etag + "\"");
        resp.setHeader("Last-Modified", HttpSupport.httpDate(lastModified));
        HttpSupport.vary(resp, "Accept");
        resp.addHeader("Link", "<" + config.storageDescriptionIri() + ">; rel=\""
                + HttpSupport.REL_STORAGE_DESCRIPTION + "\"");

        // The shared entity-tag comparison, not a substring test. `inm.contains(etag)` was a fourth
        // hand-rolled dialect and a loose one: it matched a tag that merely appeared inside a longer
        // one the client had sent.
        if (HttpSupport.ifNoneMatchMatches(req, etag)) {
            resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }
        if (HttpSupport.notModifiedSince(req, lastModified)) {
            resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }

        byte[] body;
        String contentType;
        if (rdf) {
            body = RdfIO.write(descriptions.buildModel(), fmt.writeFormat());
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
