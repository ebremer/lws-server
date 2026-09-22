package com.ebremer.lws.server.http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import jakarta.json.Json;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.AuthenticationFilter;
import com.ebremer.lws.server.core.JsonLimits;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.notifications.Subscription;
import com.ebremer.lws.server.notifications.SubscriptionService;
import com.ebremer.lws.server.rdf.RdfFormats;
import com.ebremer.lws.server.rdf.RdfIO;
import com.ebremer.lws.server.vocab.LWS;

/**
 * The {@code NotificationService} endpoint (lws10-core, Subscriptions; lws10-notifications-webhook).
 *
 * <ul>
 *   <li>{@code POST} the endpoint with an {@code application/lws+json} subscription request creates a
 *       subscription, with read authorization enforced over every topic, and answers {@code 201}
 *       with its {@code Location} and an {@code application/lws+json} body carrying {@code type},
 *       {@code subscription} and {@code expires}.</li>
 *   <li>{@code GET} the endpoint lists the caller's active subscriptions as an LWS container,
 *       paginated like any other.</li>
 *   <li>{@code GET} a subscription returns its current state; {@code DELETE} cancels it.</li>
 * </ul>
 *
 * <p>Every representation is JSON by default; a client that ranks an RDF serialization higher gets
 * RDF instead, as before.
 *
 * @author Erich Bremer
 */
public final class SubscriptionServlet extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(SubscriptionServlet.class);

    private static final String ALLOW_COLLECTION = "GET, HEAD, POST, OPTIONS";
    private static final String ALLOW_MEMBER = "GET, HEAD, DELETE, OPTIONS";

    private final transient SubscriptionService subscriptions;
    private final transient LwsConfiguration config;

    public SubscriptionServlet(SubscriptionService subscriptions, LwsConfiguration config) {
        this.subscriptions = subscriptions;
        this.config = config;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = path(req);
        boolean collection = path.equals(config.subscriptionsPath()) || path.equals(config.subscriptionsPath() + "/");
        String id = config.baseUri() + path;
        LwsPrincipal principal = AuthenticationFilter.principal(req);
        try {
            switch (req.getMethod()) {
                case "POST" -> {
                    if (!collection) {
                        throw LwsException.methodNotAllowed("POST");
                    }
                    create(req, resp, principal);
                }
                case "GET", "HEAD" -> {
                    // The endpoint and each subscription are Storage Resources (the endpoint is an
                    // LWS container), so they link to their storage like every other one.
                    HttpSupport.addStorageLink(resp, config);
                    if (collection) {
                        listCollection(req, resp, principal);
                    } else {
                        getOne(req, resp, principal, id);
                    }
                }
                case "DELETE" -> {
                    if (collection) {
                        throw LwsException.methodNotAllowed("DELETE");
                    }
                    deleteOne(resp, principal, id);
                }
                case "OPTIONS" -> {
                    resp.setHeader("Allow", collection ? ALLOW_COLLECTION : ALLOW_MEMBER);
                    if (collection) {
                        resp.setHeader("Accept-Post", HttpSupport.LWS_JSON + ", application/ld+json, application/json");
                    }
                    resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
                }
                default -> throw LwsException.methodNotAllowed(req.getMethod());
            }
        } catch (LwsException e) {
            if (e.status() == 401) {
                HttpSupport.setUnauthorizedHeaders(resp, config);
            }
            if (e.status() == 405) {
                // Mandatory on a 405 (RFC 9110 §15.5.6). AccessServlet is a near-verbatim twin of
                // this switch and gained the same line; this is the branch next to it.
                resp.setHeader("Allow", collection ? ALLOW_COLLECTION : ALLOW_MEMBER);
            }
            sendProblem(resp, e.status(), e.getMessage());
        } catch (RuntimeException e) {
            log.error("Error handling {} {}", req.getMethod(), path, e);
            sendProblem(resp, 500, "Internal server error");
        }
    }

    private void create(HttpServletRequest req, HttpServletResponse resp, LwsPrincipal principal) throws IOException {
        // Anonymous subscription is a supported configuration, so this body may arrive with no
        // credential at all: state what is acceptable before spending anything on it. The request
        // MUST be application/lws+json (lws10-core); ld+json and json are the same document.
        HttpSupport.requireJsonContentType(req);
        JsonObject request;
        byte[] raw = HttpSupport.readBody(req, config.maxRequestBytes());
        JsonLimits.requireBoundedNesting(raw);
        try (var reader = Json.createReader(new java.io.ByteArrayInputStream(raw))) {
            request = reader.readObject();
        } catch (JsonException | IllegalStateException | StackOverflowError e) {
            throw LwsException.badRequest("Invalid JSON: " + e);
        }
        Subscription sub = subscriptions.create(principal, request);
        resp.setStatus(HttpServletResponse.SC_CREATED);
        resp.setHeader("Location", sub.id());
        write(req, resp, sub, true);
    }

    /**
     * List the caller's own subscriptions, or every one if the caller controls the storage.
     *
     * <p>Anonymous callers are refused. The filter used to be {@code listFor(webId)} with no gate at
     * all, and {@code listFor(null)} matches every subscription whose {@code subscriberWebId} is
     * null — i.e. every anonymously-created one — so any unauthenticated request enumerated them,
     * inbox URLs and topics included (finding L39). Whether anonymous subscriptions can exist is
     * governed separately by {@code lws.subscriptions.allow-anonymous}; that they were readable by
     * anyone was this.
     *
     * <p>The listing is an LWS container representation (lws10-notifications-webhook requires the
     * serialization to conform to LWS containers), paginated at {@code lws.container.page-size}.
     */
    private void listCollection(HttpServletRequest req, HttpServletResponse resp, LwsPrincipal principal)
            throws IOException {
        List<Subscription> subs = subscriptions.listVisibleTo(principal);
        boolean body = req.getMethod().equals("GET");
        if (RdfFormats.prefersRdf(req.getHeader("Accept"))) {
            Model m = ModelFactory.createDefaultModel();
            m.setNsPrefix(LWS.PREFIX, LWS.NS);
            Resource c = m.createResource(config.subscriptionsEndpointIri());
            c.addProperty(RDF.type, LWS.Container);
            c.addLiteral(LWS.totalItems, (long) subs.size());
            for (Subscription s : subs) {
                c.addProperty(LWS.items, m.createResource(s.id()));
            }
            writeRdf(req, resp, m, body);
            return;
        }
        List<JsonObject> members = new ArrayList<>(subs.size());
        for (Subscription s : subs) {
            members.add(LwsJsonContainers.member(s.id(), "WebhookSubscription"));
        }
        LwsJsonContainers.Page page = LwsJsonContainers.page(members,
                LwsJsonContainers.requestedPage(req), config.containerPageSize());
        JsonObject doc = LwsJsonContainers.document(resp, config.subscriptionsEndpointIri(), page);
        LwsJsonContainers.write(req, resp, doc, body);
    }

    private void getOne(HttpServletRequest req, HttpServletResponse resp, LwsPrincipal principal, String id)
            throws IOException {
        Optional<Subscription> sub = subscriptions.get(id);
        if (sub.isEmpty()) {
            throw LwsException.notFound(id);
        }
        requireManage(principal, sub.get());
        write(req, resp, sub.get(), req.getMethod().equals("GET"));
    }

    private void deleteOne(HttpServletResponse resp, LwsPrincipal principal, String id) {
        Optional<Subscription> sub = subscriptions.get(id);
        if (sub.isEmpty()) {
            throw LwsException.notFound(id);
        }
        requireManage(principal, sub.get());
        subscriptions.delete(id);
        resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private void requireManage(LwsPrincipal principal, Subscription sub) {
        // Delegated to the service, which decides through the configured Authorizer rather than
        // reading lws.owners directly (see SubscriptionService.requireManage).
        subscriptions.requireManage(principal, sub);
    }

    /** One subscription's state: lws+json by default, RDF for a client that ranks RDF higher. */
    private void write(HttpServletRequest req, HttpServletResponse resp, Subscription sub, boolean writeBody)
            throws IOException {
        if (RdfFormats.prefersRdf(req.getHeader("Accept"))) {
            writeRdf(req, resp, subscriptions.describe(sub), writeBody);
        } else {
            LwsJsonContainers.write(req, resp, subscriptions.describeJson(sub), writeBody);
        }
    }

    private void writeRdf(HttpServletRequest req, HttpServletResponse resp, Model model, boolean writeBody)
            throws IOException {
        RdfFormats.Entry fmt = RdfFormats.negotiate(req.getHeader("Accept"));
        byte[] body = RdfIO.write(model, fmt.writeFormat());
        resp.setContentType(fmt.mediaType() + ";charset=utf-8");
        HttpSupport.vary(resp, "Accept");
        HttpSupport.setPrivateNoStore(resp);
        resp.setContentLength(body.length);
        if (writeBody) {
            resp.getOutputStream().write(body);
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
