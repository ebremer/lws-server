package com.ebremer.lws.server.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.jena.rdf.model.Model;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.rdf.RdfFormats;
import com.ebremer.lws.server.rdf.RdfIO;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Renders the server-managed LWS containers — the subscription listing and the access-request and
 * access-grant endpoints — as lws10-core container representations: {@code id}, {@code type}
 * {@code Container}, {@code totalItems} and {@code items}, paginated with {@code first},
 * {@code prev}, {@code next} and {@code last} links.
 *
 * <p>Every container, stored or server-managed, is sent in the representation
 * {@link RdfFormats#negotiateContainer} selects, through {@link #render}: the lws+json document as
 * {@code application/lws+json}, {@code application/ld+json} or {@code application/json}, or the RDF
 * that document encodes, read as JSON-LD with the bundled LWS context and written in the RDF syntax
 * asked for — with the LWS profile named in {@code Content-Type} when the client asked for it
 * (lws10-core, LWS Profile and Content Negotiation). One path for all of them is what keeps the RDF
 * of every container isomorphic to its JSON, page for page.
 *
 * @author Erich Bremer
 */
final class LwsJsonContainers {

    private LwsJsonContainers() {
    }

    /** One page of a listing: its items, the full count and where it sits among the pages. */
    record Page(List<JsonObject> items, int totalItems, int page, int pages) {
    }

    /**
     * Cut page {@code page} of {@code pageSize} out of {@code all}.
     *
     * @throws LwsException 404 for a page past the last, which is what a stale page link is
     */
    static Page page(List<JsonObject> all, int page, int pageSize) {
        int total = all.size();
        int pages = Math.max(1, (int) Math.ceil(total / (double) pageSize));
        if (page > pages) {
            throw new LwsException(404, "No such results page: " + page);
        }
        int from = (page - 1) * pageSize;
        List<JsonObject> items = from < total ? all.subList(from, Math.min(from + pageSize, total)) : List.of();
        return new Page(items, total, page, pages);
    }

    /** The {@code page} query parameter: 1 when absent, {@code 400} when it is not a positive integer. */
    static int requestedPage(HttpServletRequest req) {
        String raw = req.getParameter("page");
        if (raw == null || raw.isBlank()) {
            return 1;
        }
        try {
            int page = Integer.parseInt(raw.trim());
            if (page < 1) {
                throw LwsException.badRequest("page must be >= 1");
            }
            return page;
        } catch (NumberFormatException e) {
            throw LwsException.badRequest("Invalid page: " + raw);
        }
    }

    /** A member entry: a data resource of the given specific type, whose format is lws+json. */
    static JsonObject member(String id, String specificType) {
        return Json.createObjectBuilder()
                .add("id", id)
                .add("type", Json.createArrayBuilder().add("DataResource").add(specificType))
                .add("format", HttpSupport.LWS_JSON)
                .build();
    }

    /** The container representation of one page, with its pagination links when there is more than one. */
    static JsonObject document(HttpServletResponse resp, String containerIri, Page page) {
        // A client tells a container by its rel="type" link, as on any stored container; the
        // access request and access grant endpoints "are LWS containers" (lws10-core), and the
        // subscription list is one too.
        resp.addHeader("Link", "<" + LWS.Container.getURI() + ">; rel=\"type\"");
        JsonArrayBuilder items = Json.createArrayBuilder();
        page.items().forEach(items::add);
        if (page.pages() > 1) {
            resp.addHeader("Link", "<" + containerIri + "?page=1>; rel=\"first\"");
            if (page.page() > 1) {
                resp.addHeader("Link", "<" + containerIri + "?page=" + (page.page() - 1) + ">; rel=\"prev\"");
            }
            if (page.page() < page.pages()) {
                resp.addHeader("Link", "<" + containerIri + "?page=" + (page.page() + 1) + ">; rel=\"next\"");
            }
            resp.addHeader("Link", "<" + containerIri + "?page=" + page.pages() + ">; rel=\"last\"");
        }
        return Json.createObjectBuilder()
                .add("@context", HttpSupport.LWS_JSON_CONTEXT)
                .add("id", containerIri)
                .add("type", "Container")
                .add("totalItems", page.totalItems())
                .add("items", items)
                .build();
    }

    /** A container representation in the variant a client negotiated: its bytes and its Content-Type. */
    record Rendered(byte[] body, String contentType) {
    }

    /**
     * Render a container's {@code application/lws+json} document in the variant {@code variant}
     * names.
     *
     * <p>The JSON variants are the document as it is. An RDF variant is the RDF the document
     * encodes, written in the selected syntax: {@link RdfIO#readLwsJson}, which resolves the LWS
     * context from the bundled copy, so an RDF read of a container — any client's, on every request —
     * never makes the server fetch anything. Deriving it from the same document rather than building
     * a model beside it is what makes the RDF isomorphic to the lws+json representation "of the same
     * container state and page", which the LWS profile requires: same page, same items, same
     * {@code totalItems}, and nothing the JSON does not say.
     *
     * <p>Called once every store read the page needs has finished, so the JSON-LD processing holds
     * no transaction open.
     *
     * @param containerIri the container's IRI, the base the document's identifiers resolve against
     *                     (they are absolute already; this only makes the reading independent of it)
     */
    static Rendered render(RdfFormats.ContainerVariant variant, String containerIri, String lwsJson) {
        byte[] json = lwsJson.getBytes(StandardCharsets.UTF_8);
        String contentType = variant.contentType() + ";charset=utf-8";
        if (!variant.isRdf()) {
            return new Rendered(json, contentType);
        }
        Model model;
        try {
            model = RdfIO.readLwsJson(json, containerIri);
        } catch (IllegalArgumentException e) {
            // A document this server just wrote failed to read as JSON-LD: a server fault, not a bad
            // request, so it must not reach the servlets' IllegalArgumentException-to-400 mapping.
            throw new IllegalStateException("The representation of " + containerIri
                    + " could not be read as JSON-LD: " + e.getMessage(), e);
        }
        return new Rendered(RdfIO.write(model, variant.rdf().writeFormat()), contentType);
    }

    /**
     * Write a server-managed container listing in the representation the client negotiated, marked
     * private and varying by {@code Accept}, like a stored container's.
     */
    static void writeContainer(HttpServletRequest req, HttpServletResponse resp, String containerIri,
            JsonObject doc, boolean writeBody) throws IOException {
        Rendered rendered = render(RdfFormats.negotiateContainer(req.getHeader("Accept")), containerIri,
                doc.toString());
        resp.setContentType(rendered.contentType());
        HttpSupport.vary(resp, "Accept");
        HttpSupport.setPrivateNoStore(resp);
        resp.setContentLength(rendered.body().length);
        if (writeBody) {
            resp.getOutputStream().write(rendered.body());
        }
    }

    /**
     * Write an LWS JSON document that is not a container representation (a subscription) with the
     * JSON-family media type the client asked for, marked private: every one of these documents
     * depends on who is asking.
     */
    static void write(HttpServletRequest req, HttpServletResponse resp, JsonObject doc, boolean writeBody)
            throws IOException {
        byte[] body = doc.toString().getBytes(StandardCharsets.UTF_8);
        resp.setContentType(RdfFormats.jsonFamilyContentType(req.getHeader("Accept")) + ";charset=utf-8");
        HttpSupport.vary(resp, "Accept");
        HttpSupport.setPrivateNoStore(resp);
        resp.setContentLength(body.length);
        if (writeBody) {
            resp.getOutputStream().write(body);
        }
    }
}
