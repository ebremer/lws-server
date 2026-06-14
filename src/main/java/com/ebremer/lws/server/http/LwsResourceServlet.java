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
import com.ebremer.lws.server.core.Etags;
import com.ebremer.lws.server.core.Iris;
import com.ebremer.lws.server.core.LinksetService;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.LwsResource;
import com.ebremer.lws.server.core.ResourceRegistry.ChildDesc;
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
            if (aclService != null && aclService.isAclPath(path)) {
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
                case "OPTIONS" -> handleOptions(resp, path);
                case "POST" -> handlePost(req, resp, path, principal);
                case "PUT" -> handlePut(req, resp, path, principal);
                case "PATCH" -> handlePatch(req, resp, path, principal);
                case "DELETE" -> handleDelete(req, resp, path, principal);
                default -> {
                    resp.setHeader("Allow", String.join(", ", service.allowedMethods(path)));
                    sendProblem(resp, 405, "Method not allowed: " + req.getMethod());
                }
            }
        } catch (LwsException e) {
            if (e.status() == 401) {
                HttpSupport.setUnauthorizedHeaders(resp, config);
            }
            if (e.status() == 405 || e.status() == 409) {
                resp.setHeader("Allow", String.join(", ", service.allowedMethods(path)));
            }
            sendProblem(resp, e.status(), e.getMessage());
        } catch (IllegalArgumentException e) {
            sendProblem(resp, 400, e.getMessage());
        } catch (RuntimeException e) {
            log.error("Unexpected error handling {} {}", req.getMethod(), path, e);
            sendProblem(resp, 500, "Internal server error");
        }
    }

    private void handleRead(HttpServletRequest req, HttpServletResponse resp, String path,
            LwsPrincipal principal, boolean writeBody) throws IOException {
        ReadResult rr = service.read(path, principal);
        LwsResource meta = rr.meta();
        if (rr.isContainer()) {
            handleContainerRead(req, resp, meta, rr, writeBody);
            return;
        }
        HttpSupport.setResourceHeaders(resp, meta, config);
        addAclLink(resp, meta.iri());
        if (HttpSupport.ifNoneMatchMatches(req, meta) || HttpSupport.ifModifiedSinceNotModified(req, meta)) {
            resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }
        if (rr.isRdf()) {
            resp.setHeader("Accept-Patch", HttpSupport.ACCEPT_PATCH);
            resp.setHeader("Vary", "Accept");
            writeRdf(req, resp, rr.rdf(), writeBody);
        } else {
            writeBinary(req, resp, meta, writeBody);
        }
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
        resp.setHeader("Vary", "Accept");
        String accept = req.getHeader("Accept");

        if (RdfFormats.prefersRdf(accept)) {
            HttpSupport.setResourceHeaders(resp, meta, config); // RDF: full listing, not paginated
            if (HttpSupport.ifNoneMatchMatches(req, meta) || HttpSupport.ifModifiedSinceNotModified(req, meta)) {
                resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                return;
            }
            writeRdf(req, resp, rr.rdf(), writeBody);
            return;
        }

        List<ChildDesc> all = rr.children();
        int pageSize = config.containerPageSize();
        int total = all.size();
        int pages = Math.max(1, (int) Math.ceil(total / (double) pageSize));
        int page = parsePage(req);
        if (page > pages) {
            throw new LwsException(404, "No such results page: " + page);
        }
        boolean paginated = pages > 1;
        // A page is its own representation, so its ETag must differ per page.
        String etag = paginated ? Etags.sha16(meta.etag() + "|page=" + page) : meta.etag();
        LwsResource pageMeta = meta.withEtag(etag);
        HttpSupport.setResourceHeaders(resp, pageMeta, config);
        if (paginated) {
            addContainerPageLinks(resp, meta.iri(), page, pages);
        }
        if (HttpSupport.ifNoneMatchMatches(req, pageMeta) || HttpSupport.ifModifiedSinceNotModified(req, pageMeta)) {
            resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }
        int from = (page - 1) * pageSize;
        List<ChildDesc> items = from < total ? all.subList(from, Math.min(from + pageSize, total)) : List.of();
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

    private void writeRdf(HttpServletRequest req, HttpServletResponse resp, org.apache.jena.rdf.model.Model model,
            boolean writeBody) throws IOException {
        RdfFormats.Entry fmt = RdfFormats.negotiate(req.getHeader("Accept"));
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

    private static byte[] readVerifiedBody(HttpServletRequest req) throws IOException {
        byte[] body = HttpSupport.readBody(req);
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

    private void handleOptions(HttpServletResponse resp, String path) {
        Set<String> allow = service.allowedMethods(path);
        resp.setHeader("Allow", String.join(", ", allow));
        service.stat(path).ifPresent(meta -> {
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

    private void handlePost(HttpServletRequest req, HttpServletResponse resp, String path,
            LwsPrincipal principal) throws IOException {
        WriteRequest wr = new WriteRequest(req.getContentType(), readVerifiedBody(req),
                HttpSupport.parseTypeHint(req), req.getHeader("Slug"));
        LwsResource created = service.create(path, principal, wr);
        HttpSupport.setResourceHeaders(resp, created, config);
        addAclLink(resp, created.iri());
        resp.setHeader("Location", created.iri());
        resp.setHeader("Want-Content-Digest", DigestFields.WANT);
        resp.setStatus(HttpServletResponse.SC_CREATED);
    }

    private void handlePut(HttpServletRequest req, HttpServletResponse resp, String path,
            LwsPrincipal principal) throws IOException {
        requirePutPrecondition(req, path);
        WriteRequest wr = new WriteRequest(req.getContentType(), readVerifiedBody(req),
                HttpSupport.parseTypeHint(req), null);
        PutOutcome out = service.put(path, principal, wr);
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
        checkIfMatch(req, path);
        LwsResource updated = service.patch(path, principal, readVerifiedBody(req), req.getContentType());
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
     */
    private void applySetLinkset(HttpServletRequest req, HttpServletResponse resp, String path, boolean merge) {
        if (!prefersSetLinkset(req)) {
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
        checkIfMatch(req, path);
        String depth = req.getHeader("Depth");
        boolean recursive = depth != null && depth.trim().equalsIgnoreCase("infinity");
        service.delete(path, principal, recursive);
        resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private void checkIfMatch(HttpServletRequest req, String path) {
        service.stat(path).ifPresent(meta -> {
            if (HttpSupport.ifMatchFails(req, meta)) {
                throw new LwsException(HttpServletResponse.SC_PRECONDITION_FAILED, "Precondition Failed");
            }
        });
    }

    /**
     * Replacing an existing (ETag-bearing) resource MUST be conditional: an unconditional PUT
     * (no {@code If-Match}) is rejected with 428 Precondition Required, and a stale {@code If-Match}
     * with 412 (per lws10-core update-resource). PUT that creates a new resource is unconditional.
     */
    private void requirePutPrecondition(HttpServletRequest req, String path) {
        service.stat(path).ifPresent(meta -> {
            if (meta.etag() != null && req.getHeader("If-Match") == null) {
                throw new LwsException(428, "If-Match is required to replace an existing resource");
            }
            if (HttpSupport.ifMatchFails(req, meta)) {
                throw new LwsException(HttpServletResponse.SC_PRECONDITION_FAILED, "Precondition Failed");
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
                resp.setHeader("ETag", "\"" + linkset.etag() + "\"");
                resp.setHeader("Allow", ALLOW_LINKSET);
                resp.setHeader("Accept-Patch", HttpSupport.ACCEPT_PATCH_JSON);
                if (ifNoneMatch(req, linkset.etag())) {
                    resp.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                    return;
                }
                // Prefer: include="..." / omit="..." (the LWS PreferLinkRelations read preference).
                Set<String> include = preferenceList(req, "include");
                Set<String> omit = preferenceList(req, "omit");
                String json = (include == null && omit == null)
                        ? linkset.json()
                        : LinksetService.filterRelations(linkset.json(), include, omit);
                if (include != null || omit != null) {
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
                enforceLinksetPrecondition(req, targetPath);
                byte[] patchBody = readVerifiedBody(req);
                LinksetService.Linkset updated = patchType.equals(HttpSupport.JSON_PATCH)
                        ? linksets.jsonPatch(targetPath, patchBody)
                        : linksets.patch(targetPath, patchBody);
                resp.setHeader("ETag", "\"" + updated.etag() + "\"");
                resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            }
            case "PUT" -> {
                requireResourceAccess(principal, targetPath, targetIri, true);
                requireContentType(req, "application/linkset+json");
                enforceLinksetPrecondition(req, targetPath);
                LinksetService.Linkset updated = linksets.put(targetPath, readVerifiedBody(req));
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

    /** A linkset is readable/writable exactly when its described resource is. */
    private void requireResourceAccess(LwsPrincipal principal, String targetPath, String targetIri, boolean write) {
        if (service.stat(targetPath).isEmpty()) {
            throw LwsException.notFound(targetPath);
        }
        boolean ok = write ? service.canWrite(principal, targetIri) : service.canRead(principal, targetIri);
        if (!ok) {
            if (LwsPrincipal.isAnonymous(principal)) {
                throw LwsException.unauthorized("Authentication required for " + targetIri);
            }
            throw LwsException.forbidden("Not authorized for the metadata of " + targetIri);
        }
    }

    private void requireContentType(HttpServletRequest req, String expected) {
        String ct = req.getContentType();
        if (ct == null || !RdfFormats.stripParameters(ct).equals(expected)) {
            throw LwsException.unsupportedMediaType("Expected " + expected);
        }
    }

    /** Metadata writes MUST be conditional: no If-Match -> 428, stale If-Match -> 412 (lws10-core). */
    private void enforceLinksetPrecondition(HttpServletRequest req, String targetPath) {
        String current = linksets.get(targetPath).etag();
        String ifMatch = req.getHeader("If-Match");
        if (ifMatch == null) {
            throw new LwsException(428, "If-Match is required to modify metadata");
        }
        String token = ifMatch.trim();
        if (!token.equals("*") && !token.equals("\"" + current + "\"") && !token.equals(current)) {
            throw new LwsException(HttpServletResponse.SC_PRECONDITION_FAILED, "Precondition Failed");
        }
    }

    private static boolean ifNoneMatch(HttpServletRequest req, String etag) {
        String header = req.getHeader("If-None-Match");
        if (header == null) {
            return false;
        }
        String h = header.trim();
        if (h.equals("*")) {
            return true;
        }
        for (String token : h.split(",")) {
            String t = token.trim();
            if (t.startsWith("W/")) {
                t = t.substring(2).trim();
            }
            if (t.equals("\"" + etag + "\"") || t.equals(etag)) {
                return true;
            }
        }
        return false;
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
                requireTargetExists(targetPath);
                requireControl(principal, targetIri);
                Model acl = aclService.getAclModel(targetIri);
                if (acl.isEmpty()) {
                    throw LwsException.notFound("No ACL set for " + targetIri);
                }
                writeAcl(req, resp, acl, req.getMethod().equals("GET"));
            }
            case "PUT" -> {
                requireTargetExists(targetPath);
                requireControl(principal, targetIri);
                boolean existed = aclService.aclExistsFor(targetIri);
                Lang lang = RdfFormats.langForContentType(req.getContentType()).orElse(Lang.TURTLE);
                Model acl = RdfIO.parse(HttpSupport.readBody(req), lang, targetIri);
                aclService.putAclFor(targetIri, acl);
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
                requireTargetExists(targetPath);
                requireControl(principal, targetIri);
                aclService.deleteAclFor(targetIri);
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

    private void requireTargetExists(String targetPath) {
        if (!Iris.isRoot(targetPath) && service.stat(targetPath).isEmpty()) {
            throw LwsException.notFound("No such resource for ACL: " + targetPath);
        }
    }

    private void requireControl(LwsPrincipal principal, String targetIri) {
        if (!service.canControl(principal, targetIri)) {
            if (LwsPrincipal.isAnonymous(principal)) {
                throw LwsException.unauthorized("Authentication required to control " + targetIri);
            }
            throw LwsException.forbidden("Control permission required for " + targetIri);
        }
    }

    private void writeAcl(HttpServletRequest req, HttpServletResponse resp, Model acl, boolean writeBody)
            throws IOException {
        RdfFormats.Entry fmt = RdfFormats.negotiate(req.getHeader("Accept"));
        byte[] body = RdfIO.write(acl, fmt.writeFormat());
        resp.setContentType(fmt.mediaType() + ";charset=utf-8");
        resp.setHeader("Vary", "Accept");
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
