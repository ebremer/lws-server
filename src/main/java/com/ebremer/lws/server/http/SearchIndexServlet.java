package com.ebremer.lws.server.http;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonString;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.AuthenticationFilter;
import com.ebremer.lws.server.core.JsonLimits;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.SearchIndexService;
import com.ebremer.lws.server.core.SearchIndexService.Clause;
import com.ebremer.lws.server.core.SearchIndexService.Filter;
import com.ebremer.lws.server.core.SearchIndexService.Match;
import com.ebremer.lws.server.core.SearchIndexService.Page;
import com.ebremer.lws.server.rdf.RdfFormats;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Serves the LWS {@code TypeIndexService} and {@code TypeSearchService}
 * (<a href="https://w3c.github.io/lws-protocol/lws10-index/">lws10-index</a>) as
 * {@code application/lws+json}. The same servlet is mapped to both endpoints and dispatches on the
 * request path.
 *
 * <ul>
 *   <li><b>Type index</b> — {@code GET} the endpoint as-is; a paginated {@code TypeIndex} of the
 *       distinct types the client may see.</li>
 *   <li><b>Type search</b> — an HTTP {@code QUERY} (RFC 10008) whose body is an
 *       {@code application/lws-query+json} filter: a JSON object whose {@code type} member and
 *       relation members each hold a conjunctive-normal-form value (outer array AND, inner array
 *       OR). The result is a synthetic {@code ContainerPage}. {@code OPTIONS} advertises the method
 *       in {@code Allow} and the filter format in {@code Accept-Query}.</li>
 * </ul>
 *
 * <p><b>Pagination.</b> Both services page with {@code first}/{@code prev}/{@code next}/{@code last}
 * links, which are opaque and dereferenced with {@code GET}. A search page link carries the filter
 * itself, encoded, so it needs no state on the server; one that no longer decodes, or names a page
 * past the last, is answered {@code 404}, and the client re-sends its {@code QUERY}.
 *
 * <p><b>Errors</b> follow lws10-index: a filter that is not well-formed, or holds a value that is
 * not an absolute IRI, is {@code 400}; a missing {@code Content-Type} is {@code 400} and an
 * unsupported one {@code 415} with {@code Accept-Query}; a filter past this server's complexity
 * bound is {@code 422} — never silently narrowed —; and an {@code Accept} that excludes every JSON
 * form of the result is {@code 406}.
 *
 * <p>Both responses are authorization-filtered for the requesting principal and marked
 * {@code Cache-Control: private, no-store}, because they are client-specific.
 *
 * <p>The {@code GET} and {@code POST} search forms this servlet used to accept were the draft's
 * until 20 July 2026, when {@code QUERY} replaced both; they are gone.
 *
 * @author Erich Bremer
 */
public final class SearchIndexServlet extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(SearchIndexServlet.class);

    /** The HTTP QUERY method (RFC 10008). */
    public static final String QUERY = "QUERY";

    /** Bound on filter size; an over-complex filter is refused with 422, never silently narrowed. */
    private static final int MAX_CLAUSES = 32;
    private static final int MAX_VALUES = 256;

    /** The page-link parameter that carries an encoded search filter. */
    private static final String FILTER_PARAM = "q";

    private static final String ALLOW_INDEX = "GET, HEAD, OPTIONS";
    private static final String ALLOW_SEARCH = "OPTIONS, QUERY";
    private static final String ALLOW_SEARCH_PAGE = "GET, HEAD, OPTIONS, QUERY";

    private final transient SearchIndexService service;
    private final transient LwsConfiguration config;

    public SearchIndexServlet(SearchIndexService service, LwsConfiguration config) {
        this.service = service;
        this.config = config;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = path(req);
        boolean index = path.equals(config.typeIndexPath());
        boolean pageLink = !index && req.getParameter(FILTER_PARAM) != null;
        String method = req.getMethod();
        String allow = index ? ALLOW_INDEX : pageLink ? ALLOW_SEARCH_PAGE : ALLOW_SEARCH;
        LwsPrincipal principal = AuthenticationFilter.principal(req);
        try {
            switch (method) {
                case "GET", "HEAD" -> {
                    boolean body = method.equals("GET");
                    if (index) {
                        typeIndex(req, resp, principal, body);
                    } else if (pageLink) {
                        typeSearch(req, resp, principal, decodeFilter(req.getParameter(FILTER_PARAM)),
                                parsePage(req), body);
                    } else {
                        denied(resp, allow, method);
                    }
                }
                case QUERY -> {
                    if (index) {
                        denied(resp, allow, method);
                    }
                    typeSearch(req, resp, principal, readQuery(req), parsePage(req), true);
                }
                case "OPTIONS" -> {
                    resp.setHeader("Allow", allow);
                    if (!index) {
                        resp.setHeader("Accept-Query", HttpSupport.LWS_QUERY_JSON);
                    }
                    resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
                }
                default -> denied(resp, allow, method);
            }
        } catch (LwsException e) {
            if (e.status() == 415 && !index) {
                // lws10-index: a 415 SHOULD list the query formats this server does accept.
                resp.setHeader("Accept-Query", HttpSupport.LWS_QUERY_JSON);
            }
            if (e.status() == 405) {
                resp.setHeader("Allow", allow);
            }
            sendProblem(resp, e.status(), e.getMessage());
        } catch (RuntimeException e) {
            log.error("Error handling {} {}", method, path, e);
            sendProblem(resp, 500, "Internal server error");
        }
    }

    private void typeIndex(HttpServletRequest req, HttpServletResponse resp, LwsPrincipal principal, boolean body)
            throws IOException {
        String contentType = responseContentType(req);
        Page<String> result = service.typeIndex(principal, parsePage(req), config.searchIndexPageSize());
        requireInRange(result);
        JsonArrayBuilder items = Json.createArrayBuilder();
        for (String typeIri : result.items()) {
            items.add(Json.createObjectBuilder().add("id", typeIri));
        }
        JsonObject doc = document("TypeIndex", result.totalItems(), items);
        addPageLinks(resp, config.typeIndexEndpointIri(), null, result);
        writeJson(resp, doc, contentType, body);
    }

    private void typeSearch(HttpServletRequest req, HttpServletResponse resp, LwsPrincipal principal,
            Filter filter, int page, boolean body) throws IOException {
        String contentType = responseContentType(req);
        Page<Match> result = service.typeSearch(principal, filter, page, config.searchIndexPageSize());
        requireInRange(result);
        JsonArrayBuilder items = Json.createArrayBuilder();
        for (Match match : result.items()) {
            items.add(Json.createObjectBuilder().add("id", match.iri()).add("type", typeValue(match.types())));
        }
        JsonObject doc = document("ContainerPage", result.totalItems(), items);
        addPageLinks(resp, config.typeSearchEndpointIri(), encodeFilter(filter), result);
        writeJson(resp, doc, contentType, body);
    }

    // ----- the QUERY request -----

    /**
     * Read and parse a {@code QUERY} body, checking its media type first (RFC 10008 requires a
     * {@code Content-Type}, and it must name a format this server accepts).
     */
    private Filter readQuery(HttpServletRequest req) throws IOException {
        String contentType = req.getContentType();
        if (contentType == null || contentType.isBlank()) {
            throw LwsException.badRequest("A QUERY request must say what its body is: send Content-Type: "
                    + HttpSupport.LWS_QUERY_JSON);
        }
        if (!RdfFormats.stripParameters(contentType).equals(HttpSupport.LWS_QUERY_JSON)) {
            throw LwsException.unsupportedMediaType("Unsupported query format " + contentType
                    + "; this server accepts " + HttpSupport.LWS_QUERY_JSON);
        }
        // Bounded before parsing: this endpoint has no authorization gate in front of it at all.
        byte[] raw = HttpSupport.readBody(req, config.maxRequestBytes());
        JsonLimits.requireBoundedNesting(raw);
        JsonObject body;
        try (var reader = Json.createReader(new java.io.ByteArrayInputStream(raw))) {
            JsonStructure parsed = reader.read();
            if (!(parsed instanceof JsonObject object)) {
                throw LwsException.badRequest("A filter document must be a JSON object");
            }
            body = object;
        } catch (JsonException | IllegalStateException | StackOverflowError e) {
            throw LwsException.badRequest("Invalid JSON: " + e);
        }
        return parseFilter(body);
    }

    /**
     * Interpret an {@code application/lws-query+json} filter document.
     *
     * <p>Plain JSON, not JSON-LD: a member whose name begins with {@code @} is ignored. Every other
     * member is a constraint — {@code type}, or a link relation — whose value must be an array; each
     * element is one IRI, or a non-empty array of IRIs combined with OR, and the elements are
     * combined with AND. An empty value is no constraint at all, an empty group is refused rather
     * than ignored (it can match nothing, so ignoring it would broaden the query), duplicate groups
     * count once, and every value must be an absolute IRI.
     */
    static Filter parseFilter(JsonObject body) {
        List<Clause> clauses = new ArrayList<>();
        int values = 0;
        for (Map.Entry<String, JsonValue> entry : body.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith("@")) {
                continue;
            }
            if (entry.getValue().getValueType() != JsonValue.ValueType.ARRAY) {
                throw LwsException.badRequest("\"" + key + "\" must be an array");
            }
            Set<List<String>> groups = new LinkedHashSet<>();
            for (JsonValue element : entry.getValue().asJsonArray()) {
                List<String> group = parseElement(key, element);
                for (String value : group) {
                    if (!SearchIndexService.isAbsoluteIri(value)) {
                        throw LwsException.badRequest("\"" + key + "\" value is not an absolute IRI: " + value);
                    }
                }
                groups.add(group);
            }
            for (List<String> group : groups) {
                values += group.size();
                clauses.add(key.equals("type") ? Clause.type(group) : Clause.relation(key, group));
            }
        }
        if (clauses.size() > MAX_CLAUSES || values > MAX_VALUES) {
            // 422, not 400: the filter is well-formed and understood; it is only more than this
            // server will evaluate (lws10-index, RFC 10008 §2.4).
            throw new LwsException(422, "The filter has " + clauses.size() + " groups and " + values
                    + " values; this server evaluates at most " + MAX_CLAUSES + " and " + MAX_VALUES);
        }
        return new Filter(clauses);
    }

    /** A filter element is a single IRI (string) or an OR-group: a non-empty array of IRIs. */
    private static List<String> parseElement(String key, JsonValue element) {
        if (element.getValueType() == JsonValue.ValueType.STRING) {
            return List.of(((JsonString) element).getString());
        }
        if (element.getValueType() == JsonValue.ValueType.ARRAY) {
            if (element.asJsonArray().isEmpty()) {
                throw LwsException.badRequest("\"" + key + "\" has an empty group, which can match nothing");
            }
            Set<String> group = new LinkedHashSet<>();
            for (JsonValue inner : element.asJsonArray()) {
                if (inner.getValueType() != JsonValue.ValueType.STRING) {
                    throw LwsException.badRequest("\"" + key + "\" elements must be strings or arrays of strings");
                }
                group.add(((JsonString) inner).getString());
            }
            return List.copyOf(group);
        }
        throw LwsException.badRequest("\"" + key + "\" elements must be strings or arrays of strings");
    }

    // ----- page links -----

    /** The filter, as the opaque token a search page link carries. */
    private static String encodeFilter(Filter filter) {
        JsonObjectBuilder doc = Json.createObjectBuilder();
        Map<String, JsonArrayBuilder> byKey = new java.util.LinkedHashMap<>();
        for (Clause clause : filter.clauses()) {
            JsonArrayBuilder group = Json.createArrayBuilder();
            clause.anyOf().forEach(group::add);
            byKey.computeIfAbsent(clause.isType() ? "type" : clause.relation(), k -> Json.createArrayBuilder())
                    .add(group);
        }
        byKey.forEach(doc::add);
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(doc.build().toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * The filter a search page link carries. A token that does not decode is a page reference this
     * server does not recognize, which lws10-index answers with {@code 404}.
     */
    private Filter decodeFilter(String token) {
        JsonObject doc;
        try {
            String json = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);
            JsonLimits.requireBoundedNesting(json, JsonLimits.MAX_NESTING_DEPTH);
            try (var reader = Json.createReader(new StringReader(json))) {
                doc = reader.readObject();
            }
            return parseFilter(doc);
        } catch (RuntimeException | StackOverflowError e) {
            throw new LwsException(404, "This results page is not recognized; re-send the QUERY request");
        }
    }

    private int parsePage(HttpServletRequest req) {
        String raw = req.getParameter("page");
        if (raw == null || raw.isBlank()) {
            return 1;
        }
        try {
            int page = Integer.parseInt(raw.trim());
            if (page < 1) {
                throw new LwsException(404, "No such results page: " + raw);
            }
            return page;
        } catch (NumberFormatException e) {
            throw new LwsException(404, "No such results page: " + raw);
        }
    }

    private static void requireInRange(Page<?> page) {
        if (page.isOutOfRange()) {
            throw new LwsException(404, "No such results page: " + page.page());
        }
    }

    // ----- response building -----

    /**
     * The JSON media type to answer with, from {@code Accept}: {@code application/lws+json} unless
     * the client ranks {@code application/ld+json} or {@code application/json} higher — the body is
     * the same document — and {@code 406} if it accepts none of them.
     */
    private static String responseContentType(HttpServletRequest req) {
        String accept = req.getHeader("Accept");
        if (accept != null && !accept.isBlank()
                && RdfFormats.quality(HttpSupport.LWS_JSON, accept) <= 0
                && RdfFormats.quality(RdfFormats.JSONLD, accept) <= 0
                && RdfFormats.quality("application/json", accept) <= 0) {
            throw new LwsException(406, "This service answers with application/lws+json, which the "
                    + "request's Accept header excludes");
        }
        return RdfFormats.jsonFamilyContentType(accept);
    }

    private static JsonObject document(String type, int totalItems, JsonArrayBuilder items) {
        return Json.createObjectBuilder()
                .add("@context", HttpSupport.LWS_JSON_CONTEXT)
                .add("type", type)
                .add("totalItems", totalItems)
                .add("items", items)
                .build();
    }

    /** A single type renders as a string; multiple types as an array (matching the spec examples). */
    private static JsonValue typeValue(List<String> types) {
        if (types.size() == 1) {
            return Json.createValue(compact(types.get(0)));
        }
        JsonArrayBuilder array = Json.createArrayBuilder();
        types.forEach(t -> array.add(compact(t)));
        return array.build();
    }

    /** Compact the LWS namespace to a term name (e.g. {@code lws:DataResource} -> "DataResource"). */
    private static String compact(String typeIri) {
        return typeIri.startsWith(LWS.NS) ? typeIri.substring(LWS.NS.length()) : typeIri;
    }

    private void addPageLinks(HttpServletResponse resp, String endpoint, String filterToken, Page<?> page) {
        resp.addHeader("Link", pageLink(endpoint, filterToken, 1, "first"));
        if (page.page() > 1) {
            resp.addHeader("Link", pageLink(endpoint, filterToken, page.page() - 1, "prev"));
        }
        if (page.page() < page.pages()) {
            resp.addHeader("Link", pageLink(endpoint, filterToken, page.page() + 1, "next"));
        }
        resp.addHeader("Link", pageLink(endpoint, filterToken, page.pages(), "last"));
    }

    private static String pageLink(String endpoint, String filterToken, int page, String rel) {
        String query = (filterToken == null ? "" : FILTER_PARAM + "=" + filterToken + "&") + "page=" + page;
        return "<" + endpoint + "?" + query + ">; rel=\"" + rel + "\"";
    }

    private void writeJson(HttpServletResponse resp, JsonObject doc, String contentType, boolean writeBody)
            throws IOException {
        byte[] body = doc.toString().getBytes(StandardCharsets.UTF_8);
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType(contentType + ";charset=utf-8");
        // Private and unstored: every result is authorization-filtered for this client, and a QUERY
        // response is cacheable by default with a key that knows nothing about who asked.
        resp.setHeader("Cache-Control", "private, no-store");
        HttpSupport.vary(resp, "Accept");
        HttpSupport.vary(resp, "Authorization");
        resp.setContentLength(body.length);
        if (writeBody) {
            resp.getOutputStream().write(body);
        }
    }

    private void denied(HttpServletResponse resp, String allow, String method) {
        resp.setHeader("Allow", allow);
        throw LwsException.methodNotAllowed(method);
    }

    private void sendProblem(HttpServletResponse resp, int status, String message) throws IOException {
        if (resp.isCommitted()) {
            return;
        }
        resp.setStatus(status);
        resp.setContentType(HttpSupport.PROBLEM_JSON + ";charset=utf-8");
        byte[] body = HttpSupport.problemJson(status, message);
        resp.setContentLength(body.length);
        resp.getOutputStream().write(body);
    }

    private String path(HttpServletRequest req) {
        String uri = req.getRequestURI();
        String ctx = req.getContextPath();
        String p = (ctx != null && !ctx.isEmpty() && uri.startsWith(ctx)) ? uri.substring(ctx.length()) : uri;
        return p.isEmpty() ? "/" : p;
    }
}
