package com.ebremer.lws.server.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.rdf.RdfFormats;

/**
 * Renders the server-managed LWS containers — the subscription listing and the access-request and
 * access-grant endpoints — as lws10-core container representations: {@code id}, {@code type}
 * {@code Container}, {@code totalItems} and {@code items}, paginated with {@code first},
 * {@code prev}, {@code next} and {@code last} links, and sent as whichever of the equivalent
 * {@code application/lws+json}, {@code application/ld+json} and {@code application/json} the client
 * asked for.
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

    /**
     * Write an LWS JSON document with the JSON-family media type the client asked for, marked
     * private: every one of these listings and documents depends on who is asking.
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
