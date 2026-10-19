package com.ebremer.lws.server.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * This storage's OAuth 2.0 Protected Resource Metadata (RFC 9728), which lws10-core, Protected
 * Resource Metadata, requires and which every {@code 401} points to with its
 * {@code resource_metadata} challenge parameter (lws10-core, Authorization Server Discovery).
 *
 * <p><b>Where.</b> RFC 9728 section 3.1 puts the metadata of a resource at the resource's URL with
 * {@code /.well-known/oauth-protected-resource} inserted between the host and the path, the query
 * kept after it. For a storage under a path ({@code lws.base-uri=https://host/lws}) the metadata of
 * {@code https://host/lws/c/x} is therefore at
 * {@code https://host/.well-known/oauth-protected-resource/lws/c/x} — outside the storage's own
 * path. The fronting proxy routes that back to this server with the base path stripped, exactly as
 * it routes the authorization server's {@code /.well-known/lws-configuration/lws}: this servlet
 * receives {@code /.well-known/oauth-protected-resource/c/x}, and puts the base URI back in front.
 * {@link #metadataUrl} and {@link #resourceIri} are the two directions of that mapping and must stay
 * each other's inverse.
 *
 * <p><b>What.</b> {@code resource} is the URL the client requested, character for character: RFC
 * 9728 section 3.3 has a client discard metadata whose {@code resource} is not identical to the URL
 * it derived the metadata URL from, and lws10-core, Discovery Validation by a Client, repeats it. So
 * the path is used raw — still percent-encoded, as the client sent it and as the rest of the server
 * mints IRIs — and never decoded and re-encoded. {@code authorization_servers}, which lws10-core makes
 * REQUIRED with at least one entry, lists the issuers whose access tokens this storage accepts
 * ({@link LwsConfiguration#authorizationServers()}); when there are none no conforming document
 * exists, so the answer is {@code 404} and the challenges leave {@code resource_metadata} out. The
 * DPoP members advertise what the DPoP challenge's {@code algs} does and whether
 * {@code lws.dpop.require} refuses plain bearer tokens, as lws10-core's Sender-Constrained Tokens
 * consideration suggests.
 *
 * <p><b>Nothing about what is stored.</b> The document is the same for every path — one that names
 * an existing resource, an absent one, a private one, or no storage resource at all — apart from
 * {@code resource}, which only repeats the request. No store is consulted, so it is no existence
 * oracle and needs no authorization; and it is served without authentication, because a client
 * fetches it precisely when its credential was refused: {@code AuthenticationFilter} lets requests
 * for this servlet through without looking at their {@code Authorization} header, so a stale or
 * invalid token does not stand between a client and the document that says where to get a new one.
 *
 * @author Erich Bremer
 */
public final class ProtectedResourceMetadataServlet extends HttpServlet {

    /** The well-known path this servlet is mapped under (with {@code /*}). */
    public static final String PATH = LwsConfiguration.PROTECTED_RESOURCE_METADATA_PATH;

    private static final String ALLOW = "GET, HEAD, OPTIONS";

    private final transient LwsConfiguration config;
    private final List<String> authorizationServers;

    public ProtectedResourceMetadataServlet(LwsConfiguration config) {
        this.config = config;
        this.authorizationServers = config.authorizationServers();
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String method = req.getMethod();
        if (method.equals("OPTIONS")) {
            resp.setHeader("Allow", ALLOW);
            resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }
        if (!method.equals("GET") && !method.equals("HEAD")) {
            resp.setHeader("Allow", ALLOW);
            sendProblem(resp, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method not allowed: " + method);
            return;
        }
        String suffix = suffix(req);
        if (authorizationServers.isEmpty() || suffix == null) {
            // No authorization server, no conforming document (see the class javadoc). A raw URI that
            // does not literally continue the well-known path — the prefix itself percent-encoded,
            // which the container decodes before mapping — is no URL this server sent a client to.
            sendProblem(resp, HttpServletResponse.SC_NOT_FOUND,
                    authorizationServers.isEmpty()
                            ? "No authorization server issues access tokens for this storage"
                            : "Not a protected resource metadata URL");
            return;
        }
        byte[] body = document(resourceIri(config, suffix, req.getQueryString()))
                .getBytes(StandardCharsets.UTF_8);
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType("application/json;charset=utf-8");
        // As public as the authorization server's metadata, and for the same reason: it is derived
        // from configuration and the URL alone, so a shared cache may keep it per URL.
        resp.setHeader("Cache-Control", "public, max-age=3600");
        resp.setContentLength(body.length);
        if (method.equals("GET")) {
            resp.getOutputStream().write(body);
        }
    }

    private String document(String resource) {
        JsonArrayBuilder servers = Json.createArrayBuilder();
        authorizationServers.forEach(servers::add);
        JsonArrayBuilder algs = Json.createArrayBuilder();
        for (String alg : HttpSupport.DPOP_ALGS.split(" ")) {
            algs.add(alg);
        }
        return Json.createObjectBuilder()
                .add("resource", resource)
                .add("authorization_servers", servers)
                // Access tokens are read from the Authorization header only, never from a form
                // body or the query (RFC 6750 sections 2.2 and 2.3).
                .add("bearer_methods_supported", Json.createArrayBuilder().add("header"))
                .add("dpop_signing_alg_values_supported", algs)
                .add("dpop_bound_access_tokens_required", config.dpopRequired())
                .build().toString();
    }

    /**
     * The URL of the protected resource metadata for a request this server received: the origin of
     * {@code lws.base-uri}, the well-known path, then the path of the URL the client requested —
     * the base path followed by {@code path} — and the query, if there was one (RFC 9728 section
     * 3.1). A requested path of only {@code /}, the storage root at the root of its host, is dropped,
     * as section 3.1 requires of a terminating slash following the host.
     *
     * @param path     the request path as this server received it — raw, still percent-encoded, with
     *                 any base path already stripped by the proxy; {@code /} for the root
     * @param rawQuery the raw query string, or {@code null} when the request had none
     */
    public static String metadataUrl(LwsConfiguration config, String path, String rawQuery) {
        String base = config.baseUri();
        String basePath = config.basePath();
        String origin = base.endsWith(basePath) ? base.substring(0, base.length() - basePath.length()) : base;
        String requested = basePath + (path.startsWith("/") ? path : "/" + path);
        if (requested.equals("/")) {
            requested = "";
        }
        return origin + PATH + requested + (rawQuery == null ? "" : "?" + rawQuery);
    }

    /**
     * The resource a metadata request describes — the URL whose {@link #metadataUrl} it was — from
     * what follows the well-known path in the request this server received: {@code lws.base-uri},
     * then that suffix, then the query. An empty suffix at the root of a host is the root container,
     * whose {@code /} {@link #metadataUrl} dropped; under a base path it is the base URI itself.
     *
     * @param suffix   the raw path after {@link #PATH}: empty, or starting with {@code /}
     * @param rawQuery the raw query string, or {@code null}
     */
    public static String resourceIri(LwsConfiguration config, String suffix, String rawQuery) {
        String path = suffix.isEmpty() && config.basePath().isEmpty() ? "/" : suffix;
        return config.baseUri() + path + (rawQuery == null ? "" : "?" + rawQuery);
    }

    /**
     * The raw path after {@link #PATH}, from the request URI as received (not the decoded path
     * info), or {@code null} when the raw URI does not literally continue the well-known path.
     */
    private static String suffix(HttpServletRequest req) {
        String uri = req.getRequestURI();
        String ctx = req.getContextPath();
        String p = (ctx != null && !ctx.isEmpty() && uri.startsWith(ctx)) ? uri.substring(ctx.length()) : uri;
        if (!p.startsWith(PATH)) {
            return null;
        }
        String suffix = p.substring(PATH.length());
        return suffix.isEmpty() || suffix.startsWith("/") ? suffix : null;
    }

    private static void sendProblem(HttpServletResponse resp, int status, String message) throws IOException {
        byte[] body = HttpSupport.problemJson(status, message);
        resp.setStatus(status);
        resp.setContentType(HttpSupport.PROBLEM_JSON + ";charset=utf-8");
        resp.setContentLength(body.length);
        resp.getOutputStream().write(body);
    }
}
