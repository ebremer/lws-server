package com.ebremer.lws.server.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.Etags;
import com.ebremer.lws.server.core.StorageDescriptionService;
import com.ebremer.lws.server.rdf.RdfFormats;
import com.ebremer.lws.server.rdf.RdfIO;

/**
 * Writes the storage description, with content negotiation, for the two places it is served: the
 * storage URI itself (the root container's URI, when the client does not ask for a container
 * representation) and {@code <system-prefix>/storage-description}.
 *
 * <p>The canonical representation is {@code application/lws+cid} (lws10-core, Storage Description
 * Representation). The same JSON document is sent as {@code application/ld+json} or
 * {@code application/json} to a client that ranks one of those higher, and an RDF serialization is
 * sent to one that ranks that higher still. The description is public: it is how a client learns
 * where the root container is and which authorization server to ask, which it needs before it can
 * authenticate at all.
 *
 * @author Erich Bremer
 */
public final class StorageDescriptionResponder {

    private final StorageDescriptionService descriptions;
    private final LwsConfiguration config;
    private final Instant lastModified;

    public StorageDescriptionResponder(StorageDescriptionService descriptions, LwsConfiguration config,
            Instant lastModified) {
        this.descriptions = descriptions;
        this.config = config;
        this.lastModified = lastModified;
    }

    /** Answer a {@code GET} (with {@code writeBody}) or a {@code HEAD} for the storage description. */
    public void serve(HttpServletRequest req, HttpServletResponse resp, boolean writeBody) throws IOException {
        // Negotiate first: the entity-tag names the representation that was selected, and Vary has
        // to be on the 304 as well as the 200 (RFC 9110 §8.8.1 and §15.4.5, finding M21).
        String accept = req.getHeader("Accept");
        boolean rdf = prefersRdf(accept);
        RdfFormats.Entry fmt = rdf ? RdfFormats.negotiate(accept) : null;
        // The base tag is a hash of the canonical JSON, computed once at construction, and a valid
        // validator for the RDF rendering too because that rendering is derived from the same
        // document (finding M22).
        String etag = Etags.qualify(descriptions.etagBase(),
                rdf ? fmt.variantToken() : RdfFormats.LWS_CID_VARIANT);
        resp.setHeader("ETag", "\"" + etag + "\"");
        resp.setHeader("Last-Modified", HttpSupport.httpDate(lastModified));
        HttpSupport.vary(resp, "Accept");
        HttpSupport.addStorageLink(resp, config);

        if (HttpSupport.ifNoneMatchMatches(req, etag) || HttpSupport.notModifiedSince(req, lastModified)) {
            resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }

        byte[] body;
        String contentType;
        if (rdf) {
            body = RdfIO.write(descriptions.buildModel(), fmt.writeFormat());
            contentType = fmt.mediaType();
        } else {
            body = descriptions.buildJson().getBytes(StandardCharsets.UTF_8);
            contentType = jsonContentType(accept);
        }
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType(contentType + ";charset=utf-8");
        resp.setContentLength(body.length);
        if (writeBody) {
            resp.getOutputStream().write(body);
        }
    }

    /** RDF only when an RDF serialization is ranked strictly above every JSON form of the document. */
    private static boolean prefersRdf(String accept) {
        if (accept == null || accept.isBlank()) {
            return false;
        }
        double json = Math.max(RdfFormats.quality(RdfFormats.LWS_CID, accept),
                Math.max(RdfFormats.quality(RdfFormats.JSONLD, accept),
                        Math.max(RdfFormats.quality("application/json", accept),
                                RdfFormats.quality(RdfFormats.LWS_JSON, accept))));
        double rdf = 0.0;
        for (String type : new String[] {RdfFormats.TURTLE, RdfFormats.NTRIPLES, RdfFormats.RDFXML,
                RdfFormats.TRIG}) {
            rdf = Math.max(rdf, RdfFormats.quality(type, accept));
        }
        return rdf > json;
    }

    /**
     * {@code application/lws+cid} unless the client ranks {@code application/ld+json} or
     * {@code application/json} strictly higher; the body is the same JSON document either way.
     */
    private static String jsonContentType(String accept) {
        if (accept == null || accept.isBlank()) {
            return RdfFormats.LWS_CID;
        }
        double cid = RdfFormats.quality(RdfFormats.LWS_CID, accept);
        double ld = RdfFormats.quality(RdfFormats.JSONLD, accept);
        double json = RdfFormats.quality("application/json", accept);
        if (cid >= ld && cid >= json) {
            return RdfFormats.LWS_CID;
        }
        return ld >= json ? RdfFormats.JSONLD : "application/json";
    }
}
