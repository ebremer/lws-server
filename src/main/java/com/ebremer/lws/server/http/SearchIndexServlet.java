package com.ebremer.lws.server.http;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.SearchIndexService;
import com.ebremer.lws.server.core.SearchIndexService.Clause;
import com.ebremer.lws.server.core.SearchIndexService.Filter;
import com.ebremer.lws.server.core.SearchIndexService.Match;
import com.ebremer.lws.server.core.SearchIndexService.Page;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Serves the LWS {@code TypeIndexService} and {@code TypeSearchService}
 * (<a href="https://w3c.github.io/lws-protocol/lws10-searchindex/">lws10-searchindex</a>) as
 * {@code application/lws+json}. The same servlet is mapped to both the type-index and type-search
 * endpoints and dispatches on the request path.
 *
 * <ul>
 *   <li>Type index — {@code GET} only, no filter; returns a paginated {@code TypeIndex}.</li>
 *   <li>Type search — equivalent {@code GET} and {@code POST} forms carrying a conjunctive-normal-form
 *       filter; returns a synthetic {@code ContainerPage}. {@code GET} combines comma-separated values
 *       with OR and repeated parameters with AND; {@code POST} nests arrays (inner OR, outer AND).</li>
 * </ul>
 *
 * Both responses are authorization-filtered for the requesting principal and marked
 * {@code Cache-Control: private, no-store} because they are client-specific.
 *
 * @author Erich Bremer
 */
public final class SearchIndexServlet extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(SearchIndexServlet.class);

    /** Bound on filter size; an over-complex filter is rejected, never silently narrowed. */
    private static final int MAX_CLAUSES = 32;
    private static final int MAX_VALUES = 256;

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
        String method = req.getMethod();
        String allow = index ? "GET, HEAD, OPTIONS" : "GET, HEAD, POST, OPTIONS";
        LwsPrincipal principal = AuthenticationFilter.principal(req);
        try {
            switch (method) {
                case "GET", "HEAD" -> {
                    boolean body = method.equals("GET");
                    if (index) {
                        typeIndex(req, resp, principal, body);
                    } else {
                        typeSearch(resp, principal, parseGetFilter(req), parsePage(req), body);
                    }
                }
                case "POST" -> {
                    if (index) {
                        denied(resp, allow, method);
                    }
                    typeSearch(resp, principal, parsePostFilter(req), parsePage(req), true);
                }
                case "OPTIONS" -> {
                    resp.setHeader("Allow", allow);
                    if (!index) {
                        resp.setHeader("Accept-Post", HttpSupport.LWS_JSON);
                    }
                    resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
                }
                default -> denied(resp, allow, method);
            }
        } catch (LwsException e) {
            sendProblem(resp, e.status(), e.getMessage());
        } catch (RuntimeException e) {
            log.error("Error handling {} {}", method, path, e);
            sendProblem(resp, 500, "Internal server error");
        }
    }

    private void typeIndex(HttpServletRequest req, HttpServletResponse resp, LwsPrincipal principal, boolean body)
            throws IOException {
        Page<String> result = service.typeIndex(principal, parsePage(req), config.searchIndexPageSize());
        requireInRange(result);
        JsonArrayBuilder items = Json.createArrayBuilder();
        for (String typeIri : result.items()) {
            items.add(Json.createObjectBuilder().add("id", typeIri));
        }
        JsonObject doc = document("TypeIndex", result.totalItems(), items);
        addPageLinks(resp, config.typeIndexEndpointIri(), Filter.MATCH_ALL, result);
        writeJson(resp, doc, body);
    }

    private void typeSearch(HttpServletResponse resp, LwsPrincipal principal, Filter filter, int page, boolean body)
            throws IOException {
        Page<Match> result = service.typeSearch(principal, filter, page, config.searchIndexPageSize());
        requireInRange(result);
        JsonArrayBuilder items = Json.createArrayBuilder();
        for (Match match : result.items()) {
            items.add(Json.createObjectBuilder().add("id", match.iri()).add("type", typeValue(match.types())));
        }
        JsonObject doc = document("ContainerPage", result.totalItems(), items);
        addPageLinks(resp, config.typeSearchEndpointIri(), filter, result);
        writeJson(resp, doc, body);
    }

    // ----- filter parsing -----

    private Filter parseGetFilter(HttpServletRequest req) {
        List<Clause> clauses = new ArrayList<>();
        int values = 0;
        for (Map.Entry<String, String[]> param : req.getParameterMap().entrySet()) {
            String name = param.getKey();
            if (name.equals("page")) {
                continue;
            }
            for (String raw : param.getValue()) {
                List<String> group = splitGroup(raw);
                if (group.isEmpty()) {
                    continue;
                }
                group.forEach(SearchIndexServlet::requireAbsoluteUri);
                values += group.size();
                clauses.add(name.equals("type") ? Clause.type(group) : Clause.relation(name, group));
            }
        }
        checkComplexity(clauses.size(), values);
        return new Filter(clauses);
    }

    private Filter parsePostFilter(HttpServletRequest req) throws IOException {
        String contentType = req.getContentType();
        if (contentType == null || !contentType.toLowerCase().startsWith(HttpSupport.LWS_JSON)) {
            throw LwsException.unsupportedMediaType("POST body must be " + HttpSupport.LWS_JSON);
        }
        JsonObject body;
        try (var reader = Json.createReader(req.getInputStream())) {
            JsonStructure parsed = reader.read();
            if (!(parsed instanceof JsonObject object)) {
                throw LwsException.badRequest("Request body must be a JSON object");
            }
            body = object;
        } catch (JsonException | IllegalStateException e) {
            throw LwsException.badRequest("Invalid JSON: " + e.getMessage());
        }
        List<Clause> clauses = new ArrayList<>();
        int values = 0;
        for (Map.Entry<String, JsonValue> entry : body.entrySet()) {
            String key = entry.getKey();
            if (key.equals("@context")) {
                continue;
            }
            if (entry.getValue().getValueType() != JsonValue.ValueType.ARRAY) {
                throw LwsException.badRequest("\"" + key + "\" must be an array");
            }
            for (JsonValue element : entry.getValue().asJsonArray()) {
                List<String> group = parseElement(key, element);
                group.forEach(SearchIndexServlet::requireAbsoluteUri);
                values += group.size();
                clauses.add(key.equals("type") ? Clause.type(group) : Clause.relation(key, group));
            }
        }
        checkComplexity(clauses.size(), values);
        return new Filter(clauses);
    }

    /** A POST filter element is a single URI (string) or an OR-group of URIs (array of strings). */
    private static List<String> parseElement(String key, JsonValue element) {
        if (element.getValueType() == JsonValue.ValueType.STRING) {
            return List.of(((JsonString) element).getString());
        }
        if (element.getValueType() == JsonValue.ValueType.ARRAY) {
            List<String> group = new ArrayList<>();
            for (JsonValue inner : element.asJsonArray()) {
                if (inner.getValueType() != JsonValue.ValueType.STRING) {
                    throw LwsException.badRequest("\"" + key + "\" elements must be strings or arrays of strings");
                }
                group.add(((JsonString) inner).getString());
            }
            return group;
        }
        throw LwsException.badRequest("\"" + key + "\" elements must be strings or arrays of strings");
    }

    private static List<String> splitGroup(String raw) {
        List<String> group = new ArrayList<>();
        for (String token : raw.split(",")) {
            String t = token.trim();
            if (!t.isEmpty()) {
                group.add(t);
            }
        }
        return group;
    }

    private static void requireAbsoluteUri(String value) {
        if (!SearchIndexService.isAbsoluteUri(value)) {
            throw LwsException.badRequest("Not a syntactically valid absolute URI: " + value);
        }
    }

    private static void checkComplexity(int clauses, int values) {
        if (clauses > MAX_CLAUSES || values > MAX_VALUES) {
            throw LwsException.badRequest("Filter exceeds the supported complexity");
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
                throw LwsException.badRequest("page must be >= 1");
            }
            return page;
        } catch (NumberFormatException e) {
            throw LwsException.badRequest("Invalid page: " + raw);
        }
    }

    private static void requireInRange(Page<?> page) {
        if (page.isOutOfRange()) {
            throw new LwsException(404, "No such results page: " + page.page());
        }
    }

    // ----- response building -----

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

    private void addPageLinks(HttpServletResponse resp, String endpoint, Filter filter, Page<?> page) {
        String query = filterQuery(filter);
        resp.addHeader("Link", pageLink(endpoint, query, 1, "first"));
        if (page.page() > 1) {
            resp.addHeader("Link", pageLink(endpoint, query, page.page() - 1, "prev"));
        }
        if (page.page() < page.pages()) {
            resp.addHeader("Link", pageLink(endpoint, query, page.page() + 1, "next"));
        }
        resp.addHeader("Link", pageLink(endpoint, query, page.pages(), "last"));
    }

    private static String pageLink(String endpoint, String query, int page, String rel) {
        String url = endpoint + "?" + (query.isEmpty() ? "" : query + "&") + "page=" + page;
        return "<" + url + ">; rel=\"" + rel + "\"";
    }

    /** Render a filter back to its canonical GET query string (so POST page links resolve as GET). */
    private static String filterQuery(Filter filter) {
        List<String> parts = new ArrayList<>();
        for (Clause clause : filter.clauses()) {
            String key = clause.isType() ? "type" : clause.relation();
            parts.add(encode(key) + "=" + encode(String.join(",", clause.anyOf())));
        }
        return String.join("&", parts);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private void writeJson(HttpServletResponse resp, JsonObject doc, boolean writeBody) throws IOException {
        byte[] body = doc.toString().getBytes(StandardCharsets.UTF_8);
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType(HttpSupport.LWS_JSON + ";charset=utf-8");
        resp.setHeader("Cache-Control", "private, no-store");
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
