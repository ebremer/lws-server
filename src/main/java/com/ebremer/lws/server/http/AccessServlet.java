package com.ebremer.lws.server.http;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.AuthenticationFilter;
import com.ebremer.lws.server.core.AccessService;
import com.ebremer.lws.server.core.AccessService.Kind;
import com.ebremer.lws.server.core.AccessService.Record;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.notifications.NotificationEmitter;
import com.ebremer.lws.server.rdf.RdfFormats;

/**
 * Serves the LWS {@code AccessRequestService} and {@code AccessGrantService} endpoints
 * (<a href="https://w3c.github.io/lws-protocol/lws10-core/#access-requests">lws10-core access
 * requests</a>) as {@code application/lws+json}. Each endpoint behaves as an LWS container:
 *
 * <ul>
 *   <li>{@code POST} the collection creates a request/grant ({@code 201} + {@code Location}). Any
 *       authenticated agent may submit a request; only a storage controller may issue a grant.</li>
 *   <li>{@code GET} the collection lists the entries the caller may see; {@code GET} an entry
 *       retrieves it.</li>
 *   <li>{@code DELETE} an entry cancels a request or revokes a grant.</li>
 * </ul>
 *
 * One servlet instance serves both endpoints and dispatches on the request path.
 *
 * @author Erich Bremer
 */
public final class AccessServlet extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(AccessServlet.class);

    private final transient AccessService access;
    private final transient ResourceService resources;
    private final transient LwsConfiguration config;
    private final transient NotificationEmitter notifications;
    private final transient Clock clock;

    public AccessServlet(AccessService access, ResourceService resources, LwsConfiguration config,
            NotificationEmitter notifications, Clock clock) {
        this.access = access;
        this.resources = resources;
        this.config = config;
        this.notifications = notifications;
        this.clock = clock;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = path(req);
        Kind kind = path.equals(config.accessRequestsPath()) || path.startsWith(config.accessRequestsPath() + "/")
                ? Kind.REQUEST : Kind.GRANT;
        String collectionPath = kind == Kind.REQUEST ? config.accessRequestsPath() : config.accessGrantsPath();
        boolean collection = path.equals(collectionPath) || path.equals(collectionPath + "/");
        String id = config.baseUri() + path;
        LwsPrincipal principal = AuthenticationFilter.principal(req);
        try {
            switch (req.getMethod()) {
                case "POST" -> {
                    if (!collection) {
                        throw LwsException.methodNotAllowed("POST");
                    }
                    create(req, resp, kind, principal);
                }
                case "GET", "HEAD" -> {
                    boolean body = req.getMethod().equals("GET");
                    if (collection) {
                        listCollection(resp, kind, principal, body);
                    } else {
                        getOne(resp, kind, principal, id, body);
                    }
                }
                case "DELETE" -> {
                    if (collection) {
                        throw LwsException.methodNotAllowed("DELETE");
                    }
                    deleteOne(resp, kind, principal, id);
                }
                case "OPTIONS" -> {
                    resp.setHeader("Allow", collection ? "GET, HEAD, POST, OPTIONS" : "GET, HEAD, DELETE, OPTIONS");
                    if (collection) {
                        resp.setHeader("Accept-Post", HttpSupport.LWS_JSON);
                    }
                    resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
                }
                default -> throw LwsException.methodNotAllowed(req.getMethod());
            }
        } catch (LwsException e) {
            if (e.status() == 401) {
                HttpSupport.setUnauthorizedHeaders(resp, config);
            }
            sendProblem(resp, e.status(), e.getMessage());
        } catch (RuntimeException e) {
            log.error("Error handling {} {}", req.getMethod(), path, e);
            sendProblem(resp, 500, "Internal server error");
        }
    }

    private void create(HttpServletRequest req, HttpServletResponse resp, Kind kind, LwsPrincipal principal)
            throws IOException {
        if (LwsPrincipal.isAnonymous(principal)) {
            throw LwsException.unauthorized("Authentication required");
        }
        if (kind == Kind.GRANT && !isController(principal)) {
            throw LwsException.forbidden("Only a storage controller may issue access grants");
        }
        requireJsonContentType(req);
        Record record = access.create(principal, kind, HttpSupport.readBody(req));
        // SHOULD: notify the relevant inboxes — the document's own inbox, the storage controller
        // (new request), and the associated request's inbox (new grant).
        for (String inbox : access.notificationInboxes(record)) {
            notifications.notifyAccessCreated(inbox, record.id(), kind == Kind.GRANT,
                    principal.webId(), clock.instant());
        }
        resp.setStatus(HttpServletResponse.SC_CREATED);
        resp.setHeader("Location", record.id());
        writeJson(resp, record.json(), true);
    }

    private void listCollection(HttpServletResponse resp, Kind kind, LwsPrincipal principal, boolean body)
            throws IOException {
        boolean controller = isController(principal);
        String collectionIri = kind == Kind.REQUEST ? config.accessRequestsEndpointIri()
                : config.accessGrantsEndpointIri();
        String type = kind == Kind.REQUEST ? "AccessRequest" : "AccessGrant";
        JsonArrayBuilder items = Json.createArrayBuilder();
        int count = 0;
        for (Record record : access.all(kind)) {
            if (controller || canView(principal, record)) {
                items.add(Json.createObjectBuilder().add("id", record.id()).add("type", type));
                count++;
            }
        }
        JsonObject doc = Json.createObjectBuilder()
                .add("@context", HttpSupport.LWS_JSON_CONTEXT)
                .add("id", collectionIri)
                .add("type", "Container")
                .add("totalItems", count)
                .add("items", items)
                .build();
        writeJson(resp, doc.toString(), body);
    }

    private void getOne(HttpServletResponse resp, Kind kind, LwsPrincipal principal, String id, boolean body)
            throws IOException {
        Record record = access.get(id).orElseThrow(() -> LwsException.notFound(id));
        if (record.kind() != kind) {
            throw LwsException.notFound(id);
        }
        if (!isController(principal) && !canView(principal, record)) {
            denied(principal);
        }
        writeJson(resp, record.json(), body);
    }

    private void deleteOne(HttpServletResponse resp, Kind kind, LwsPrincipal principal, String id) {
        Record record = access.get(id).orElseThrow(() -> LwsException.notFound(id));
        if (record.kind() != kind) {
            throw LwsException.notFound(id);
        }
        if (!isController(principal) && !isCreator(principal, record)) {
            denied(principal);
        }
        access.delete(id);
        resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    // ----- authorization helpers -----

    /** A storage controller is an agent with Control over the storage root. */
    private boolean isController(LwsPrincipal principal) {
        return !LwsPrincipal.isAnonymous(principal) && resources.canControl(principal, config.storageRootIri());
    }

    private static boolean isCreator(LwsPrincipal principal, Record record) {
        return !LwsPrincipal.isAnonymous(principal) && principal.webId().equals(record.creator());
    }

    /** A request/grant is viewable by its creator, and a grant additionally by its assignee. */
    private static boolean canView(LwsPrincipal principal, Record record) {
        if (isCreator(principal, record)) {
            return true;
        }
        return record.kind() == Kind.GRANT && !LwsPrincipal.isAnonymous(principal)
                && assignees(record.json()).contains(principal.webId());
    }

    private static void denied(LwsPrincipal principal) {
        if (LwsPrincipal.isAnonymous(principal)) {
            throw LwsException.unauthorized("Authentication required");
        }
        throw LwsException.forbidden("Not authorized");
    }

    private static List<String> assignees(String json) {
        List<String> out = new java.util.ArrayList<>();
        try (var reader = Json.createReader(new StringReader(json))) {
            JsonObject doc = reader.readObject();
            if (doc.containsKey("access") && doc.get("access").getValueType() == JsonValue.ValueType.ARRAY) {
                for (JsonValue policy : doc.getJsonArray("access")) {
                    if (policy.getValueType() == JsonValue.ValueType.OBJECT) {
                        JsonValue assignee = policy.asJsonObject().get("assignee");
                        if (assignee != null && assignee.getValueType() == JsonValue.ValueType.STRING) {
                            out.add(((jakarta.json.JsonString) assignee).getString());
                        }
                    }
                }
            }
        } catch (RuntimeException ignored) {
            // malformed stored document: no assignees
        }
        return out;
    }

    // ----- response helpers -----

    private void requireJsonContentType(HttpServletRequest req) {
        String ct = req.getContentType();
        String mt = ct == null ? "" : RdfFormats.stripParameters(ct);
        if (!mt.equals(HttpSupport.LWS_JSON) && !mt.equals("application/ld+json") && !mt.equals("application/json")) {
            throw LwsException.unsupportedMediaType("Request body must be " + HttpSupport.LWS_JSON);
        }
    }

    private void writeJson(HttpServletResponse resp, String json, boolean body) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        if (resp.getStatus() != HttpServletResponse.SC_CREATED) {
            resp.setStatus(HttpServletResponse.SC_OK);
        }
        resp.setContentType(HttpSupport.LWS_JSON + ";charset=utf-8");
        resp.setHeader("Cache-Control", "private, no-store");
        resp.setContentLength(bytes.length);
        if (body) {
            resp.getOutputStream().write(bytes);
        }
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
