package com.ebremer.lws.server.http;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.riot.Lang;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.AuthenticationFilter;
import com.ebremer.lws.server.auth.WacAclService;
import com.ebremer.lws.server.core.AclMode;
import com.ebremer.lws.server.core.Etags;
import com.ebremer.lws.server.core.IfMatch;
import com.ebremer.lws.server.core.IfNoneMatch;
import com.ebremer.lws.server.core.Iris;
import com.ebremer.lws.server.core.LinksetService;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.LwsResource;
import com.ebremer.lws.server.core.ResourceRegistry.ChildDesc;
import com.ebremer.lws.server.core.ResourceRegistry.ChildRef;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.core.ResourceService.PutOutcome;
import com.ebremer.lws.server.core.ResourceService.ReadResult;
import com.ebremer.lws.server.core.ResourceService.WriteRequest;
import com.ebremer.lws.server.core.ResourceType;
import com.ebremer.lws.server.rdf.RdfFormats;
import com.ebremer.lws.server.rdf.RdfIO;

/**
 * The catch-all LWS resource servlet. It maps HTTP methods to {@link ResourceService}
 * operations over the containment hierarchy and renders responses with content negotiation,
 * Link relations, conditional-request handling and protocol status codes.
 *
 * @author Erich Bremer
 */
public final class LwsResourceServlet extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(LwsResourceServlet.class);

    private final transient ResourceService service;
    private final transient LwsConfiguration config;
    private final transient WacAclService aclService; // nullable: only when WAC is enabled
    private final transient LinksetService linksets;

    public LwsResourceServlet(ResourceService service, LwsConfiguration config, WacAclService aclService,
            LinksetService linksets) {
        this.service = service;
        this.config = config;
        this.aclService = aclService;
        this.linksets = linksets;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = path(req);
        LwsPrincipal principal = AuthenticationFilter.principal(req);
        try {
            if (aclService != null && Iris.isAclPath(path)) {
                handleAcl(req, resp, path, principal);
                return;
            }
            if (Iris.isLinksetPath(path)) {
                handleLinkset(req, resp, path, principal);
                return;
            }
            if (config.isSystemPath(path)) {
                throw LwsException.notFound(path);
            }
            switch (req.getMethod()) {
                case "GET" -> handleRead(req, resp, path, principal, true);
                case "HEAD" -> handleRead(req, resp, path, principal, false);
                case "OPTIONS" -> handleOptions(resp, path, principal);
                case "POST" -> handlePost(req, resp, path, principal);
                case "PUT" -> handlePut(req, resp, path, principal);
                case "PATCH" -> handlePatch(req, resp, path, principal);
                case "DELETE" -> handleDelete(req, resp, path, principal);
                default -> {
                    resp.setHeader("Allow", String.join(", ", service.allowedMethods(path, principal)));
                    HttpSupport.setPrivateNoStore(resp);
                    sendProblem(resp, 405, "Method not allowed: " + req.getMethod());
                }
            }
        } catch (LwsException e) {
            if (e.status() == 401) {
                HttpSupport.setUnauthorizedHeaders(resp, config);
            }
            // Allow lists the methods the target supports, so it is right for a state conflict
            // ("not a container", "container is not empty") but wrong for a reserved name, where
            // advertising PUT would invite a retry of the request just permanently refused.
            if (e.status() == 405 || (e.status() == 409 && !config.isReservedPath(path))) {
                resp.setHeader("Allow", String.join(", ", service.allowedMethods(path, principal)));
                // Allow now varies by principal, and 405 is heuristically cacheable (RFC 9110
                // 15.1). Without this a shared cache could serve one client's view to another.
                HttpSupport.setPrivateNoStore(resp);
            }
            sendProblem(resp, e.status(), e.getMessage());
        } catch (IllegalArgumentException e) {
            sendProblem(resp, 400, e.getMessage());
        } catch (RuntimeException e) {
            log.error("Unexpected error handling {} {}", req.getMethod(), path, e);
            sendProblem(resp, 500, "Internal server error");
        }
    }

    /**
     * Read a non-container resource.
     *
     * <p>For an RDF source the serialization is chosen <em>first</em>, and everything that depends on
     * it — the entity-tag, {@code Vary}, {@code Accept-Patch} — is set before the conditional check
     * rather than after it (finding M21). Two RFC 9110 requirements were being missed at once. The
     * tag was the stored one, shared by all five serializations, so a client holding a cached Turtle
     * representation asked for JSON-LD and was told {@code 304 Not Modified} — of the Turtle
     * (&sect;8.8.1). And {@code Vary: Accept} was set two lines <em>below</em> the {@code 304}
     * return, so the one response that most needs it, the one a cache stores against a key, never
     * carried it (&sect;15.4.5).
     */
    private void handleRead(HttpServletRequest req, HttpServletResponse resp, String path,
            LwsPrincipal principal, boolean writeBody) throws IOException {
        ReadResult rr = service.read(path, principal);
        LwsResource meta = rr.meta();
        if (rr.isContainer()) {
            handleContainerRead(req, resp, meta, rr, writeBody);
            return;
        }
        if (rr.isRdf()) {
            RdfFormats.Entry fmt = RdfFormats.negotiate(req.getHeader("Accept"));
            LwsResource representation = meta.withEtag(Etags.qualify(meta.etag(), fmt.variantToken()));
            HttpSupport.setResourceHeaders(resp, representation, config);
            addAclLink(resp, meta.iri());
            resp.setHeader("Accept-Patch", HttpSupport.ACCEPT_PATCH);
            HttpSupport.vary(resp, "Accept");
            if (HttpSupport.ifNoneMatchMatches(req, representation)
                    || HttpSupport.ifModifiedSinceNotModified(req, representation)) {
                resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                return;
            }
            writeRdf(resp, rr.rdf(), fmt, req, writeBody);
            return;
        }
        // A non-RDF resource has exactly one representation — the bytes as stored — so its tag needs
        // no variant and its response does not vary on Accept.
        HttpSupport.setResourceHeaders(resp, meta, config);
        addAclLink(resp, meta.iri());
        if (HttpSupport.ifNoneMatchMatches(req, meta) || HttpSupport.ifModifiedSinceNotModified(req, meta)) {
            resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }
        writeBinary(req, resp, meta, writeBody);
    }

    /**
     * Read a container: the canonical {@code application/lws+json} listing (paginated when the
     * membership exceeds {@code lws.container.page-size}, with {@code first}/{@code prev}/{@code next}/
     * {@code last} Link relations and the requested JSON {@code Content-Type} echoed), or RDF — the
     * full listing — when an RDF type is explicitly preferred.
     */
    private void handleContainerRead(HttpServletRequest req, HttpServletResponse resp, LwsResource meta,
            ReadResult rr, boolean writeBody) throws IOException {
        addAclLink(resp, meta.iri());
        resp.setHeader("Accept-Post", HttpSupport.ACCEPT_POST);
        HttpSupport.vary(resp, "Accept");
        // The listing is filtered to what THIS client may read, so two principals get different
        // bodies from the same URL under the same entity-tag. It must never be held by a shared
        // cache (and the ETag is a concurrency token for writers, not a cache validator here).
        resp.setHeader("Cache-Control", "private, no-store");
        String accept = req.getHeader("Accept");

        if (RdfFormats.prefersRdf(accept)) {
            // RDF: the full listing, not paginated — but still one representation among several, so
            // its tag is qualified like any other (finding M21). Without this the Turtle rendering
            // and the lws+json one shared a tag, and a client that had read one was told 304 for the
            // other.
            RdfFormats.Entry fmt = RdfFormats.negotiate(accept);
            LwsResource representation = meta.withEtag(Etags.qualify(meta.etag(), fmt.variantToken()));
            HttpSupport.setResourceHeaders(resp, representation, config);
            if (HttpSupport.ifNoneMatchMatches(req, representation)
                    || HttpSupport.ifModifiedSinceNotModified(req, representation)) {
                resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                return;
            }
            // Built here and not by service.read: the JSON branch below never needs it, and it used
            // to be built for every container GET including the ones that answer 304 (finding M23).
            writeRdf(resp, service.containerRepresentation(meta, rr.children()), fmt, req, writeBody);
            return;
        }

        List<ChildRef> all = rr.children();
        int pageSize = config.containerPageSize();
        int total = all.size();
        int pages = Math.max(1, (int) Math.ceil(total / (double) pageSize));
        int page = parsePage(req);
        if (page > pages) {
            throw new LwsException(404, "No such results page: " + page);
        }
        boolean paginated = pages > 1;
        // A page is its own representation, so its ETag must differ per page — and the JSON
        // rendering is a different representation from the Turtle one above, so the whole thing is
        // then qualified as lws+json. The page number goes into the hashed half rather than the
        // variant half deliberately: a page tag must NOT satisfy an If-Match on the container, since
        // a client that read page 2 has not read the state a write would replace. `namesState`
        // strips only the variant token, so `<state>.lwsjson` names the state and
        // `sha16(<state>|page=2).lwsjson` does not.
        String etag = paginated ? Etags.sha16(meta.etag() + "|page=" + page) : meta.etag();
        LwsResource pageMeta = meta.withEtag(Etags.qualify(etag, RdfFormats.LWS_JSON_VARIANT));
        HttpSupport.setResourceHeaders(resp, pageMeta, config);
        if (paginated) {
            addContainerPageLinks(resp, meta.iri(), page, pages);
        }
        if (HttpSupport.ifNoneMatchMatches(req, pageMeta) || HttpSupport.ifModifiedSinceNotModified(req, pageMeta)) {
            resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }
        int from = (page - 1) * pageSize;
        List<ChildRef> window = from < total ? all.subList(from, Math.min(from + pageSize, total)) : List.of();
        // The media type, size and modified time of one page's members — not of the whole
        // membership, which is what made page 1 of a 200,000-member container cost the same as page
        // 200 (finding M23). The window is bounded by lws.container.page-size.
        List<ChildDesc> items = service.describe(meta.iri(), window.stream().map(ChildRef::iri).toList());
        byte[] body = containerJson(meta, items, total).getBytes(StandardCharsets.UTF_8);
        resp.setContentType(RdfFormats.jsonFamilyContentType(accept) + ";charset=utf-8");
        addDigests(req, resp, body);
        resp.setContentLength(body.length);
        if (writeBody) {
            resp.getOutputStream().write(body);
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

    private static void addContainerPageLinks(HttpServletResponse resp, String iri, int page, int pages) {
        resp.addHeader("Link", "<" + iri + "?page=1>; rel=\"first\"");
        if (page > 1) {
            resp.addHeader("Link", "<" + iri + "?page=" + (page - 1) + ">; rel=\"prev\"");
        }
        if (page < pages) {
            resp.addHeader("Link", "<" + iri + "?page=" + (page + 1) + ">; rel=\"next\"");
        }
        resp.addHeader("Link", "<" + iri + "?page=" + pages + ">; rel=\"last\"");
    }

    /** Serialize a model in an already-negotiated format; the caller negotiates so the tag can too. */
    private void writeRdf(HttpServletResponse resp, org.apache.jena.rdf.model.Model model,
            RdfFormats.Entry fmt, HttpServletRequest req, boolean writeBody) throws IOException {
        byte[] body = RdfIO.write(model, fmt.writeFormat());
        resp.setContentType(fmt.mediaType() + ";charset=utf-8");
        addDigests(req, resp, body);
        resp.setContentLength(body.length);
        if (writeBody) {
            resp.getOutputStream().write(body);
        }
    }

    /** Emit RFC 9530 Repr-Digest / Content-Digest for an in-memory representation when requested. */
    private static void addDigests(HttpServletRequest req, HttpServletResponse resp, byte[] representation) {
        DigestFields.chooseAlgorithm(req.getHeader("Want-Repr-Digest"), DigestFields.SUPPORTED_SET)
                .ifPresent(alg -> resp.setHeader("Repr-Digest", DigestFields.format(alg, representation)));
        DigestFields.chooseAlgorithm(req.getHeader("Want-Content-Digest"), DigestFields.SUPPORTED_SET)
                .ifPresent(alg -> resp.setHeader("Content-Digest", DigestFields.format(alg, representation)));
    }

    /** Emit digests for a non-RDF resource from its persisted SHA-256 (Repr-Digest is the full content). */
    private static void addBinaryDigests(HttpServletRequest req, HttpServletResponse resp, LwsResource meta,
            boolean partial) {
        if (meta.digest() == null) {
            return;
        }
        if (DigestFields.chooseAlgorithm(req.getHeader("Want-Repr-Digest"), Set.of("sha-256")).isPresent()) {
            resp.setHeader("Repr-Digest", DigestFields.sha256FromHex(meta.digest()));
        }
        // Content-Digest is the digest of the bytes actually sent; only equals the full content for a
        // non-range response, so it is omitted for partial (206) responses.
        if (!partial && DigestFields.chooseAlgorithm(req.getHeader("Want-Content-Digest"), Set.of("sha-256")).isPresent()) {
            resp.setHeader("Content-Digest", DigestFields.sha256FromHex(meta.digest()));
        }
    }

    private byte[] readVerifiedBody(HttpServletRequest req) throws IOException {
        byte[] body = HttpSupport.readBody(req, config.maxRequestBytes());
        DigestFields.verify(req.getHeader("Content-Digest"), body); // RFC 9530 inbound integrity check
        return body;
    }

    /**
     * The LWS container representation as {@code application/lws+json} (lws10-core). {@code items}
     * is the current page; {@code totalItems} reflects the full membership.
     */
    private static String containerJson(LwsResource container, List<ChildDesc> pageItems, int totalItems) {
        jakarta.json.JsonArrayBuilder items = jakarta.json.Json.createArrayBuilder();
        for (ChildDesc child : pageItems) {
            jakarta.json.JsonObjectBuilder item = jakarta.json.Json.createObjectBuilder()
                    .add("type", child.container() ? "Container" : "DataResource")
                    .add("id", child.iri());
            if (!child.container() && child.mediaType() != null) {
                item.add("mediaType", child.mediaType());
            }
            if (child.size() >= 0) {
                item.add("size", child.size());
            }
            if (child.modified() != null) {
                item.add("modified", child.modified().toString());
            }
            items.add(item);
        }
        return jakarta.json.Json.createObjectBuilder()
                .add("@context", HttpSupport.LWS_JSON_CONTEXT)
                .add("id", container.iri())
                .add("type", "Container")
                .add("totalItems", totalItems)
                .add("items", items)
                .build().toString();
    }

    /** Serve a non-RDF resource, honouring a single HTTP byte range (RFC 7233). */
    private void writeBinary(HttpServletRequest req, HttpServletResponse resp, LwsResource meta, boolean writeBody)
            throws IOException {
        if (RdfFormats.isJson(meta.contentType())) {
            resp.setHeader("Accept-Patch", HttpSupport.ACCEPT_PATCH_JSON);
        }
        resp.setContentType(meta.contentType() == null ? "application/octet-stream" : meta.contentType());
        HttpSupport.setContentSecurityHeaders(resp, meta);
        resp.setHeader("Accept-Ranges", "bytes");
        long size = meta.size();
        long[] range = size >= 0 ? HttpSupport.parseByteRange(req.getHeader("Range"), size) : null;
        if (range != null && range.length == 1) { // syntactically a byte range, but unsatisfiable
            resp.setHeader("Content-Range", "bytes */" + size);
            resp.setStatus(416);
            return;
        }
        if (range != null) {
            long start = range[0];
            long end = range[1];
            long length = end - start + 1;
            resp.setStatus(HttpServletResponse.SC_PARTIAL_CONTENT);
            resp.setHeader("Content-Range", "bytes " + start + "-" + end + "/" + size);
            addBinaryDigests(req, resp, meta, true);
            resp.setContentLengthLong(length);
            if (writeBody) {
                try (InputStream in = service.openBinary(meta)) {
                    in.skipNBytes(start);
                    copy(in, resp.getOutputStream(), length);
                }
            }
            return;
        }
        addBinaryDigests(req, resp, meta, false);
        if (size >= 0) {
            resp.setContentLengthLong(size);
        }
        if (writeBody) {
            try (InputStream in = service.openBinary(meta)) {
                in.transferTo(resp.getOutputStream());
            }
        }
    }

    private static void copy(InputStream in, java.io.OutputStream out, long length) throws IOException {
        byte[] buffer = new byte[8192];
        long remaining = length;
        int read;
        while (remaining > 0 && (read = in.read(buffer, 0, (int) Math.min(buffer.length, remaining))) != -1) {
            out.write(buffer, 0, read);
            remaining -= read;
        }
    }

    /**
     * Answer {@code OPTIONS}, for a caller allowed to know the resource is there.
     *
     * <p>It used to take no principal at all: {@code Allow}, {@code Accept-Post} and
     * {@code Accept-Patch} were computed from the stored resource and returned to anyone. That is an
     * existence oracle with a type attached — an unauthenticated request could tell a container from
     * a JSON blob from an RDF source, and tell either from a path with nothing at it.
     */
    private void handleOptions(HttpServletResponse resp, String path, LwsPrincipal principal) {
        String iri = Iris.toIri(config.baseUri(), path);
        // An anonymous client is still told to authenticate, whether or not anything is stored
        // here — otherwise OPTIONS is the oracle every other method just stopped being.
        if (LwsPrincipal.isAnonymous(principal) && !service.canRead(principal, iri)) {
            throw LwsException.unauthorized("Authentication required for " + iri);
        }
        // For everyone else this answers a resource they may not read exactly as it answers one
        // that is not there: allowedMethods already masks the type, and describing it below is
        // skipped for the same reason. No refusal is raised, because a 404 here and a 204 there
        // would be the same disclosure with the codes swapped.
        boolean describable = config.maskForbiddenAsNotFound() ? service.canRead(principal, iri) : true;
        Set<String> allow = service.allowedMethods(path, principal);
        resp.setHeader("Allow", String.join(", ", allow));
        // The 204 below is heuristically cacheable and its headers now depend on who asked, so it
        // must not be shared. AccessServlet and the container listing already do this.
        HttpSupport.setPrivateNoStore(resp);
        service.stat(path).filter(meta -> describable).ifPresent(meta -> {
            if (meta.isContainer()) {
                resp.setHeader("Accept-Post", HttpSupport.ACCEPT_POST);
            } else if (meta.type() == ResourceType.RDF_SOURCE) {
                resp.setHeader("Accept-Patch", HttpSupport.ACCEPT_PATCH);
            } else if (RdfFormats.isJson(meta.contentType())) {
                resp.setHeader("Accept-Patch", HttpSupport.ACCEPT_PATCH_JSON);
            }
        });
        resp.setHeader("Want-Content-Digest", DigestFields.WANT); // invite integrity-protected writes
        resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * Refuse a write the caller plainly cannot perform <em>before</em> its body is read.
     *
     * <p>The authoritative check still happens inside the write transaction; this is only a
     * pre-filter, so it is deliberately permissive — it rejects only when denial is already
     * certain. Without it, a request destined for 401/403 still costs the server a full body
     * buffer first, which is what makes an unauthorized writer expensive.
     */
    private void requireWriteBeforeBody(HttpServletRequest req, String path, LwsPrincipal principal,
            boolean intoContainer) {
        String iri = Iris.toIri(config.baseUri(), path);
        boolean allowed;
        if (intoContainer) {
            allowed = service.canAppend(principal, iri);
        } else {
            // A PUT may be a replace (Write on the target) or a create (Append on its parent).
            String parentPath = Iris.parentPath(path);
            allowed = service.canWrite(principal, iri)
                    || (parentPath != null
                            && service.canAppend(principal, Iris.toIri(config.baseUri(), parentPath)));
        }
        if (!allowed) {
            // Through the same helper the service uses, so this pre-filter cannot disclose by
            // answering 403 what the authoritative check a moment later would have masked as 404.
            // A control that two code paths implement differently is a control with a way around it.
            throw service.refusalFor(principal, iri,
                    intoContainer ? AclMode.APPEND : AclMode.WRITE);
        }
    }

    private void handlePost(HttpServletRequest req, HttpServletResponse resp, String path,
            LwsPrincipal principal) throws IOException {
        requireWriteBeforeBody(req, path, principal, true);
        WriteRequest wr = new WriteRequest(req.getContentType(), readVerifiedBody(req),
                HttpSupport.parseTypeHint(req), req.getHeader("Slug"));
        LwsResource created = service.create(path, principal, wr);
        // A POST can declare the new resource's types too — the server chose its name, so this is
        // the first chance the client has to say what it is.
        applyDeclaredTypes(req, Iris.toPath(config.baseUri(), created.iri()));
        HttpSupport.setResourceHeaders(resp, created, config);
        addAclLink(resp, created.iri());
        resp.setHeader("Location", created.iri());
        resp.setHeader("Want-Content-Digest", DigestFields.WANT);
        resp.setStatus(HttpServletResponse.SC_CREATED);
    }

    private void handlePut(HttpServletRequest req, HttpServletResponse resp, String path,
            LwsPrincipal principal) throws IOException {
        IfMatch ifMatch = HttpSupport.ifMatch(req);
        IfNoneMatch ifNoneMatch = HttpSupport.ifNoneMatch(req);
        requireWriteBeforeBody(req, path, principal, false);
        requirePutPrecondition(req, path, principal, ifMatch, ifNoneMatch);
        WriteRequest wr = new WriteRequest(req.getContentType(), readVerifiedBody(req),
                HttpSupport.parseTypeHint(req), null);
        PutOutcome out = service.put(path, principal, wr, ifMatch, ifNoneMatch);
        HttpSupport.setResourceHeaders(resp, out.resource(), config);
        addAclLink(resp, out.resource().iri());
        resp.setHeader("Want-Content-Digest", DigestFields.WANT);
        applySetLinkset(req, resp, path, false); // Prefer: set-linkset — replace linkset from Link headers
        if (out.created()) {
            resp.setHeader("Location", out.resource().iri());
            resp.setStatus(HttpServletResponse.SC_CREATED);
        } else {
            resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
        }
    }

    private void handlePatch(HttpServletRequest req, HttpServletResponse resp, String path,
            LwsPrincipal principal) throws IOException {
        IfMatch ifMatch = HttpSupport.ifMatch(req);
        requireWriteBeforeBody(req, path, principal, false);
        checkIfMatch(path, principal, ifMatch);
        LwsResource updated = service.patch(path, principal, readVerifiedBody(req), req.getContentType(),
                ifMatch);
        HttpSupport.setResourceHeaders(resp, updated, config);
        addAclLink(resp, updated.iri());
        resp.setHeader("Want-Content-Digest", DigestFields.WANT);
        applySetLinkset(req, resp, path, true); // Prefer: set-linkset — partial linkset update from Link headers
        resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * Honour {@code Prefer: set-linkset} (RFC 7240, lws10-core update-resource): after the content
     * write, apply the request's {@code Link} headers to the resource's linkset — a replacement on
     * PUT, a partial update on PATCH. Off by default (the preference must be set explicitly), so a
     * normal write never touches metadata. The content and metadata writes are sequential, not a
     * single transaction; the linkset write is validated cheaply, so a partial outcome is unlikely.
     *
     * <p><b>The metadata write is unconditional</b>, even though a direct {@code PUT} or
     * {@code PATCH} of {@code <resource>.meta} requires an {@code If-Match} (finding L28). It has to
     * be: the request carries one {@code If-Match}, which names the version of the <em>content</em>
     * being replaced, and HTTP has no way to carry a second precondition for a second resource. A
     * client that needs its metadata write to be conditional makes it against the linkset resource,
     * where it is. The same applies to {@link #applyDeclaredTypes}.
     */
    private void applySetLinkset(HttpServletRequest req, HttpServletResponse resp, String path, boolean merge) {
        if (!prefersSetLinkset(req)) {
            applyDeclaredTypes(req, path);
            return;
        }
        Map<String, List<String>> links = HttpSupport.parseLinks(req);
        if (merge) {
            linksets.mergeFromLinks(path, links);
        } else {
            linksets.replaceFromLinks(path, links);
        }
        resp.setHeader("Preference-Applied", "set-linkset");
    }

    /**
     * Record any {@code Link: rel="type"} the client sent as a declared type of the resource
     * (lws10-searchindex, which makes this the preferred way to say what a resource is).
     *
     * <p>Not gated on {@code Prefer: set-linkset}. That preference is how a client replaces or merges
     * its <em>whole</em> metadata document from headers, and demanding it here would mean a
     * conformant {@code Link: rel="type"} was ignored unless the client also asked for something
     * else. Only the type relation is applied, and only the IRIs {@code LinksetService} accepts —
     * the LWS namespace and the LDP interaction models are refused, so a client can describe its
     * resource and cannot claim to be a container. When the preference <em>is</em> set, the general
     * path above already carries the types and this does not run a second write.
     */
    private void applyDeclaredTypes(HttpServletRequest req, String path) {
        List<String> declared = HttpSupport.parseLinks(req).get("type");
        if (declared == null || declared.isEmpty()) {
            return;
        }
        linksets.mergeFromLinks(path, Map.of("type", declared));
    }

    private static boolean prefersSetLinkset(HttpServletRequest req) {
        var e = req.getHeaders("Prefer");
        while (e != null && e.hasMoreElements()) {
            for (String token : e.nextElement().split(",")) {
                if (token.trim().equalsIgnoreCase("set-linkset")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Parse a {@code Prefer} preference of the form {@code name=value} or {@code name="v1 v2"} into
     * its space-separated tokens, or {@code null} if absent. Used for the LWS PreferLinkRelations
     * {@code include}/{@code omit} read preference (whose wire syntax the spec leaves open).
     */
    private static Set<String> preferenceList(HttpServletRequest req, String name) {
        var e = req.getHeaders("Prefer");
        while (e != null && e.hasMoreElements()) {
            for (String token : e.nextElement().split(",")) {
                String t = token.trim();
                if (!t.regionMatches(true, 0, name + "=", 0, name.length() + 1)) {
                    continue;
                }
                String value = t.substring(name.length() + 1).trim();
                if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }
                Set<String> rels = new LinkedHashSet<>();
                for (String rel : value.split("\\s+")) {
                    if (!rel.isBlank()) {
                        rels.add(rel.trim());
                    }
                }
                return rels;
            }
        }
        return null;
    }

    private void handleDelete(HttpServletRequest req, HttpServletResponse resp, String path,
            LwsPrincipal principal) {
        String depth = req.getHeader("Depth");
        boolean recursive = depth != null && depth.trim().equalsIgnoreCase("infinity");
        service.delete(path, principal, recursive, HttpSupport.ifMatch(req));
        resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * Refuse a stale {@code If-Match} before the request body is read.
     *
     * <p>Advisory only. It reads the entity-tag in a transaction of its own, which had closed by the
     * time the write opened, so it can never be the thing that makes a conditional write safe: the
     * compare-and-swap that does lives inside the write transaction, in {@code ResourceService}
     * (finding H23). What this buys is the same thing {@code requireWriteBeforeBody} buys — a
     * request that is certainly doomed is refused without first reading up to
     * {@code lws.max-request-bytes} of body for it.
     *
     * <p>It therefore runs <em>after</em> {@code requireWriteBeforeBody}, matching the order the
     * transaction itself uses: a caller who may not write here is told so, rather than being told
     * through a 412 or a 428 whether the resource exists and which tag it carries. DELETE, which has
     * no body to bound, does not pre-check at all.
     */
    private void checkIfMatch(String path, LwsPrincipal principal, IfMatch ifMatch) {
        if (!mayLearnTheTag(path, principal)) {
            return;
        }
        service.stat(path).ifPresent(meta -> {
            if (!ifMatch.satisfiedBy(meta)) {
                throw LwsException.preconditionFailed("Precondition Failed");
            }
        });
    }

    /**
     * Whether this caller may be told a precondition's answer about {@code path}.
     *
     * <p>{@code requireWriteBeforeBody} is deliberately permissive — a caller with Append on the
     * parent passes it — so on its own it does not stop the two precondition checks below from
     * answering {@code 428} or {@code 412} for a target the caller may not read, while its
     * {@code GET} is masked as {@code 404}. Measured: an append-only drop-box client could read off
     * which names were taken, and which entity-tag each carried, one conditional request at a time.
     *
     * <p>Skipping the check is safe, and is not a hole: these are advisory early-outs that exist to
     * refuse a doomed request before its body is read. The authoritative comparison happens inside
     * the write transaction, which is where authorization happens too, so a caller who may not read
     * simply gets its answer a little later and from the code that was always entitled to give it.
     */
    private boolean mayLearnTheTag(String path, LwsPrincipal principal) {
        return !config.maskForbiddenAsNotFound()
                || service.canRead(principal, Iris.toIri(config.baseUri(), path));
    }

    /**
     * Replacing an existing (ETag-bearing) resource MUST be conditional: an unconditional PUT
     * (no {@code If-Match}) is rejected with 428 Precondition Required, and a stale {@code If-Match}
     * with 412 (per lws10-core update-resource). PUT that creates a new resource is unconditional.
     *
     * <p>The 412 here is the same advisory early-out as {@link #checkIfMatch}; the authoritative
     * comparison happens inside the write transaction. The 428 is a protocol rule rather than a
     * precondition, and still lives only here (finding M20).
     */
    private void requirePutPrecondition(HttpServletRequest req, String path, LwsPrincipal principal,
            IfMatch ifMatch, IfNoneMatch ifNoneMatch) {
        if (!mayLearnTheTag(path, principal)) {
            return; // see mayLearnTheTag: the authoritative check is inside the write transaction
        }
        service.stat(path).ifPresent(meta -> {
            // If-None-Match: * is a conditional request too — "create only if nothing is here" — so
            // it satisfies the rule rather than being answered 428 for want of a tag naming a
            // version the client is asserting does not exist. It then gets the 412 it asked for,
            // below. A tag LIST does not qualify: see ResourceService.requireConditionalReplace.
            if (meta.etag() != null && !ifMatch.isPresent() && !ifNoneMatch.isStar()) {
                throw LwsException.preconditionRequired(
                        "If-Match is required to replace an existing resource");
            }
            if (!ifMatch.satisfiedBy(meta) || !ifNoneMatch.satisfiedBy(meta)) {
                throw LwsException.preconditionFailed("Precondition Failed");
            }
        });
    }

    // ----- Linkset (metadata) resources: <resource>.meta, served as application/linkset+json -----

    private static final String ALLOW_LINKSET = "GET, HEAD, PATCH, PUT, OPTIONS";

    private void handleLinkset(HttpServletRequest req, HttpServletResponse resp, String path, LwsPrincipal principal)
            throws IOException {
        String targetPath = Iris.linksetTargetPath(path);
        if (config.isSystemPath(targetPath)) {
            throw LwsException.notFound(path);
        }
        String targetIri = Iris.toIri(config.baseUri(), targetPath);
        switch (req.getMethod()) {
            case "GET", "HEAD" -> {
                requireResourceAccess(principal, targetPath, targetIri, false);
                LinksetService.Linkset linkset = linksets.get(targetPath);
                resp.setHeader("Allow", ALLOW_LINKSET);
                resp.setHeader("Accept-Patch", HttpSupport.ACCEPT_PATCH_JSON);
                // Prefer: include="..." / omit="..." (the LWS PreferLinkRelations read preference).
                // Resolved BEFORE the entity-tag, because a filtered document is a different
                // representation of the same resource and must not carry the full document's tag
                // (RFC 9110 section 8.8.1, the same rule as M21's per-serialization tags). It used
                // to share it, so a client that had read `Prefer: include="describedby"` and then
                // revalidated without the preference was answered 304 and kept the filtered document
                // as though it were the whole thing. The response varies by Prefer, which it now
                // says as well.
                Set<String> include = preferenceList(req, "include");
                Set<String> omit = preferenceList(req, "omit");
                boolean filtered = include != null || omit != null;
                HttpSupport.vary(resp, "Prefer");
                String etag = filtered
                        ? Etags.sha16(linkset.etag() + "|" + (include != null ? "include" : "omit")
                                + "=" + String.join(" ", include != null ? include : omit))
                        : linkset.etag();
                resp.setHeader("ETag", "\"" + etag + "\"");
                if (HttpSupport.ifNoneMatchMatches(req, etag)) {
                    resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                    return;
                }
                String json = filtered
                        ? LinksetService.filterRelations(linkset.json(), include, omit)
                        : linkset.json();
                if (filtered) {
                    resp.setHeader("Preference-Applied", include != null ? "include" : "omit");
                }
                byte[] body = json.getBytes(StandardCharsets.UTF_8);
                resp.setContentType("application/linkset+json;charset=utf-8");
                resp.setContentLength(body.length);
                if (req.getMethod().equals("GET")) {
                    resp.getOutputStream().write(body);
                }
            }
            case "PATCH" -> {
                requireResourceAccess(principal, targetPath, targetIri, true);
                String patchType = RdfFormats.stripParameters(
                        req.getContentType() == null ? "" : req.getContentType());
                if (!patchType.equals(HttpSupport.MERGE_PATCH) && !patchType.equals(HttpSupport.JSON_PATCH)) {
                    throw LwsException.unsupportedMediaType("Expected " + HttpSupport.ACCEPT_PATCH_JSON);
                }
                IfMatch ifMatch = enforceLinksetPrecondition(req, targetPath);
                byte[] patchBody = readVerifiedBody(req);
                LinksetService.Linkset updated = patchType.equals(HttpSupport.JSON_PATCH)
                        ? linksets.jsonPatch(targetPath, patchBody, ifMatch)
                        : linksets.patch(targetPath, patchBody, ifMatch);
                resp.setHeader("ETag", "\"" + updated.etag() + "\"");
                resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            }
            case "PUT" -> {
                requireResourceAccess(principal, targetPath, targetIri, true);
                requireContentType(req, "application/linkset+json");
                IfMatch ifMatch = enforceLinksetPrecondition(req, targetPath);
                LinksetService.Linkset updated = linksets.put(targetPath, readVerifiedBody(req), ifMatch);
                resp.setHeader("ETag", "\"" + updated.etag() + "\"");
                resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            }
            case "OPTIONS" -> {
                resp.setHeader("Allow", ALLOW_LINKSET);
                resp.setHeader("Accept-Patch", HttpSupport.ACCEPT_PATCH_JSON);
                resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            }
            default -> {
                resp.setHeader("Allow", ALLOW_LINKSET);
                sendProblem(resp, 405, "Method not allowed: " + req.getMethod());
            }
        }
    }

    /**
     * A linkset is readable/writable exactly when its described resource is.
     *
     * <p>{@code write} means {@link com.ebremer.lws.server.core.AclMode#WRITE}, deliberately, and not
     * {@code DELETE} — a linkset has no {@code DELETE} of its own ({@link #ALLOW_LINKSET}), and the
     * only ways to remove one are a PUT of an empty document, which is a modification, and deleting
     * the described resource, which is authorized as a delete of <em>that</em>. So the mode split
     * added for access grants (finding M8) leaves this path exactly where it was: a grant naming only
     * {@code modify} governs the metadata, as it governs the content.
     */
    /**
     * Gate a metadata ({@code .meta}) request on its target resource.
     *
     * <p>Through the same helpers the resource path uses, and for the same reason. {@code /x.meta}
     * is a total function of {@code /x}, so answering "no such resource" here for one target and
     * "not authorized" for another restored, for every resource in the storage, exactly the
     * existence oracle the resource path had just closed. Measured before this: a hidden
     * {@code /x.meta} answered {@code 403} and an absent one {@code 404}, in both authorization
     * modes, and anonymously it was {@code 401} versus {@code 404}.
     */
    private void requireResourceAccess(LwsPrincipal principal, String targetPath, String targetIri, boolean write) {
        AclMode mode = write ? AclMode.WRITE : AclMode.READ;
        if (service.stat(targetPath).isEmpty()) {
            throw service.absenceFor(principal, targetIri, mode);
        }
        boolean ok = write ? service.canWrite(principal, targetIri) : service.canRead(principal, targetIri);
        if (!ok) {
            throw service.refusalFor(principal, targetIri, mode);
        }
    }

    private void requireContentType(HttpServletRequest req, String expected) {
        String ct = req.getContentType();
        if (ct == null || !RdfFormats.stripParameters(ct).equals(expected)) {
            throw LwsException.unsupportedMediaType("Expected " + expected);
        }
    }

    /**
     * Metadata writes MUST be conditional: no If-Match -> 428, stale If-Match -> 412 (lws10-core).
     * Returns the precondition so the write can re-compare it under the writer lock, where the
     * comparison is a compare-and-swap rather than the advisory early-out it is here (finding M18).
     */
    private IfMatch enforceLinksetPrecondition(HttpServletRequest req, String targetPath) {
        IfMatch ifMatch = HttpSupport.ifMatch(req);
        if (!ifMatch.isPresent()) {
            throw LwsException.preconditionRequired("If-Match is required to modify metadata");
        }
        if (!ifMatch.matches(linksets.get(targetPath).etag())) {
            throw LwsException.preconditionFailed("Precondition Failed");
        }
        return ifMatch;
    }

    // ----- Web Access Control: ACL resources (governed by acl:Control on the target) -----

    private void addAclLink(HttpServletResponse resp, String iri) {
        if (aclService != null) {
            resp.addHeader("Link", "<" + aclService.aclIriFor(iri) + ">; rel=\"acl\"");
        }
    }

    private void handleAcl(HttpServletRequest req, HttpServletResponse resp, String path, LwsPrincipal principal)
            throws IOException {
        String targetPath = aclService.targetPathOf(path);
        String targetIri = config.baseUri() + targetPath;
        switch (req.getMethod()) {
            case "GET", "HEAD" -> {
                requireTargetExists(principal, targetPath, targetIri);
                requireControl(principal, targetIri);
                // One read for the body and the tag together. Taken separately they are two
                // snapshots, and a write landing between them hands the client a body from one
                // version under a tag naming the next — so a write it then conditions on that tag
                // passes a precondition against a version it never saw, which is the lost update the
                // tag exists to prevent.
                WacAclService.AclSnapshot snapshot = aclService.readAcl(targetIri);
                Model acl = snapshot.model();
                if (acl.isEmpty()) {
                    throw LwsException.notFound("No ACL set for " + targetIri);
                }
                // An ACL carries an entity-tag, so a client can name the version it is about to
                // replace — which is what makes a conditional ACL write possible at all
                // (prior-review finding 13). Negotiated first, and the tag qualified per
                // serialization, exactly as every other RDF read is (finding M21).
                RdfFormats.Entry fmt = RdfFormats.negotiate(req.getHeader("Accept"));
                String etag = Etags.qualify(snapshot.etag(), fmt.variantToken());
                HttpSupport.vary(resp, "Accept");
                if (etag != null) {
                    resp.setHeader("ETag", "\"" + etag + "\"");
                    if (HttpSupport.ifNoneMatchMatches(req, etag)) {
                        resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                        return;
                    }
                }
                writeAcl(resp, acl, fmt, req.getMethod().equals("GET"));
            }
            case "PUT" -> {
                requireTargetExists(principal, targetPath, targetIri);
                requireControl(principal, targetIri);
                boolean existed = aclService.aclExistsFor(targetIri);
                Lang lang = RdfFormats.langForContentType(req.getContentType()).orElse(Lang.TURTLE);
                // readVerifiedBody, not readBody: every other body-reading write in this servlet
                // verifies an RFC 9530 Content-Digest when the client sends one, and an ACL is the
                // last body that should be exempt from an integrity check.
                Model acl = RdfIO.parse(readVerifiedBody(req), lang, targetIri);
                aclService.putAclFor(principal, targetIri, acl, HttpSupport.ifMatch(req),
                        HttpSupport.ifNoneMatch(req));
                if (existed) {
                    resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
                } else {
                    resp.setHeader("Location", aclService.aclIriFor(targetIri));
                    resp.setStatus(HttpServletResponse.SC_CREATED);
                }
            }
            case "DELETE" -> {
                if (Iris.isRoot(targetPath)) {
                    throw LwsException.forbidden("The root ACL cannot be deleted");
                }
                requireTargetExists(principal, targetPath, targetIri);
                requireControl(principal, targetIri);
                aclService.deleteAclFor(principal, targetIri, HttpSupport.ifMatch(req));
                resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            }
            case "OPTIONS" -> {
                resp.setHeader("Allow", "GET, HEAD, PUT, DELETE, OPTIONS");
                resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            }
            default -> {
                resp.setHeader("Allow", "GET, HEAD, PUT, DELETE, OPTIONS");
                sendProblem(resp, 405, "Method not allowed: " + req.getMethod());
            }
        }
    }

    /**
     * Refuse an ACL request whose target does not exist.
     *
     * <p>Masked like every other absence, and this surface needs it most: under Web Access Control
     * "has an own ACL" is very nearly the same fact as "exists", so an endpoint that answers
     * {@code 404} for one target and {@code 403} for another is answering that question directly,
     * for any resource the caller cares to name.
     */
    private void requireTargetExists(LwsPrincipal principal, String targetPath, String targetIri) {
        if (!Iris.isRoot(targetPath) && service.stat(targetPath).isEmpty()) {
            throw service.absenceFor(principal, targetIri, AclMode.CONTROL);
        }
    }

    private void requireControl(LwsPrincipal principal, String targetIri) {
        if (!service.canControl(principal, targetIri)) {
            throw service.refusalFor(principal, targetIri, AclMode.CONTROL);
        }
    }

    private void writeAcl(HttpServletResponse resp, Model acl, RdfFormats.Entry fmt, boolean writeBody)
            throws IOException {
        byte[] body = RdfIO.write(acl, fmt.writeFormat());
        resp.setContentType(fmt.mediaType() + ";charset=utf-8");
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
