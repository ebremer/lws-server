package com.ebremer.lws.server.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import jakarta.json.JsonArray;
import jakarta.json.JsonValue;
import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdfconnection.RDFConnection;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFFormat;
import org.apache.jena.update.UpdateAction;
import org.apache.jena.update.UpdateRequest;
import org.apache.jena.vocabulary.DCTerms;
import org.apache.jena.vocabulary.RDF;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.rdf.RdfFormats;
import com.ebremer.lws.server.rdf.RdfIO;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.storage.BinaryStore;
import com.ebremer.lws.server.vocab.LWS;

/**
 * The core LWS protocol engine: read/create/update/delete over the containment hierarchy,
 * with content negotiation, containment representation, authorization and change events.
 *
 * <p>This class is intentionally free of any servlet or framework type so it can be reused by
 * the HTTP layer, the Wicket UI and the notification subsystem, and unit-tested directly.
 *
 * @author Erich Bremer
 */
public final class ResourceService {

    private static final Logger log = LoggerFactory.getLogger(ResourceService.class);

    /** What a client asked to be created (resolved from Link rel="type" headers / paths). */
    public enum TypeHint { AUTO, CONTAINER, RDF_SOURCE, NON_RDF_SOURCE }

    /** A request body to write (POST/PUT). */
    public record WriteRequest(String contentType, byte[] body, TypeHint typeHint, String slug) {
    }

    /**
     * The result of reading a resource: metadata, an RDF representation (null for non-RDF data
     * resources), and — for containers — the child descriptors for the listing.
     */
    public record ReadResult(LwsResource meta, Model rdf, List<ResourceRegistry.ChildDesc> children) {
        /** True if an RDF model is available (a container or an RDF data resource). */
        public boolean isRdf() {
            return rdf != null;
        }

        /** True if this is a container (its {@link #children} listing is available). */
        public boolean isContainer() {
            return children != null;
        }
    }

    /** The result of a PUT: the resource plus whether it was newly created. */
    public record PutOutcome(LwsResource resource, boolean created) {
    }

    private final RdfStore rdf;
    private final BinaryStore blobs;
    private final ResourceRegistry registry;
    private final Authorizer authorizer;
    private final LwsConfiguration config;
    private final Clock clock;
    private final List<ResourceEventListener> listeners = new CopyOnWriteArrayList<>();

    public ResourceService(RdfStore rdf, BinaryStore blobs, ResourceRegistry registry,
            Authorizer authorizer, LwsConfiguration config, Clock clock) {
        this.rdf = rdf;
        this.blobs = blobs;
        this.registry = registry;
        this.authorizer = authorizer;
        this.config = config;
        this.clock = clock;
    }

    public void addEventListener(ResourceEventListener listener) {
        listeners.add(listener);
    }

    /** Create the storage root container if it does not yet exist. */
    public void ensureStorageRoot() {
        String iri = config.storageRootIri();
        rdf.writeDo(conn -> {
            if (!registry.exists(conn, iri)) {
                Instant now = now();
                String owner = config.ownerWebIds().stream().findFirst().orElse(null);
                LwsResource root = new LwsResource(iri, ResourceType.CONTAINER, null, now, now,
                        Etags.of(iri, now.toString()), null, -1, null, owner, config.publicReadDefault(), null);
                registry.put(conn, root);
                log.info("Initialized storage root {}", iri);
            }
        });
    }

    // ----- Reads -----

    public Optional<LwsResource> stat(String path) {
        String iri = pathToIri(path);
        return rdf.read(conn -> registry.find(conn, iri));
    }

    public ReadResult read(String path, LwsPrincipal principal) {
        String iri = pathToIri(path);
        ReadResult loaded = rdf.read(conn -> {
            LwsResource meta = registry.find(conn, iri).orElseThrow(() -> LwsException.notFound(iri));
            authorize(principal, iri, AclMode.READ);
            switch (meta.type()) {
                case CONTAINER -> {
                    return new ReadResult(meta, null, registry.childDescriptions(conn, meta.iri()));
                }
                case RDF_SOURCE -> {
                    // Copy out of the transaction: conn.fetch() returns a store-backed model that
                    // is only valid while the transaction is open.
                    Model copy = ModelFactory.createDefaultModel().add(conn.fetch(iri));
                    return new ReadResult(meta, copy, null);
                }
                default -> {
                    return new ReadResult(meta, null, null);
                }
            }
        });
        if (!loaded.isContainer()) {
            return loaded;
        }
        // Filter members to those the client may read: the listing — and therefore totalItems —
        // reflects only the disclosable view (lws10-core). Evaluated outside the read transaction so
        // the authorizer can open its own connection, and is client-specific by construction.
        List<ResourceRegistry.ChildDesc> visible = loaded.children().stream()
                .filter(child -> authorizer.allows(principal, child.iri(), AclMode.READ))
                .toList();
        Model rep = containerRepresentation(loaded.meta(), visible);
        return new ReadResult(loaded.meta().withEtag(Etags.forModel(rep)), rep, visible);
    }

    /** Open the bytes of a non-RDF resource. Caller closes the stream. */
    public InputStream openBinary(LwsResource meta) throws IOException {
        return blobs.read(meta.binaryKey());
    }

    private Model containerRepresentation(LwsResource container, List<ResourceRegistry.ChildDesc> children) {
        Model m = ModelFactory.createDefaultModel();
        m.setNsPrefix(LWS.PREFIX, LWS.NS);
        m.setNsPrefix("dcterms", DCTerms.getURI());
        Resource c = m.createResource(container.iri());
        c.addProperty(RDF.type, LWS.Container);
        c.addProperty(LWS.storageDescription, m.createResource(config.storageDescriptionIri()));
        if (container.modified() != null) {
            c.addProperty(DCTerms.modified,
                    m.createTypedLiteral(container.modified().toString(), XSDDatatype.XSDdateTime));
        }
        for (ResourceRegistry.ChildDesc child : children) {
            Resource cr = m.createResource(child.iri());
            c.addProperty(LWS.items, cr);
            cr.addProperty(RDF.type, child.container() ? LWS.Container : LWS.DataResource);
        }
        return m;
    }

    // ----- Create (POST into a container) -----

    public LwsResource create(String containerPath, LwsPrincipal principal, WriteRequest req) {
        String containerIri = pathToIri(containerPath);
        ResourceEvent[] ev = new ResourceEvent[1];
        LwsResource result = rdf.write(conn -> {
            LwsResource container = registry.find(conn, containerIri)
                    .orElseThrow(() -> LwsException.notFound(containerIri));
            if (!container.isContainer()) {
                throw LwsException.conflict("Target is not a container: " + containerIri);
            }
            authorize(principal, containerIri, AclMode.APPEND);
            ResourceType type = resolveType(req, false, req.slug() != null && req.slug().endsWith("/"));
            String name = chooseName(conn, containerPath, req.slug(), type);
            String childPath = containerPath + name + (type == ResourceType.CONTAINER ? "/" : "");
            String childIri = pathToIri(childPath);
            Instant now = now();
            LwsResource child = storeContent(conn, childIri, childPath, type, req,
                    now, now, ownerFor(principal, container), config.publicReadDefault());
            registry.put(conn, child);
            registry.put(conn, container.withModified(now));
            ev[0] = new ResourceEvent(ActivityKind.CREATE, childIri, type, webId(principal), now);
            return child;
        });
        emit(ev[0]);
        return result;
    }

    // ----- Put (create or replace at an exact IRI) -----

    public PutOutcome put(String path, LwsPrincipal principal, WriteRequest req) {
        if (Iris.isRoot(path)) {
            throw LwsException.badRequest("Cannot PUT the storage root");
        }
        String iri = pathToIri(path);
        boolean[] created = {false};
        ResourceEvent[] ev = new ResourceEvent[1];
        LwsResource result = rdf.write(conn -> {
            Optional<LwsResource> existing = registry.find(conn, iri);
            Instant now = now();
            if (existing.isPresent()) {
                LwsResource cur = existing.get();
                authorize(principal, iri, AclMode.WRITE);
                ResourceType reqType = resolveType(req, true, Iris.isContainerPath(path));
                if (reqType != cur.type()) {
                    throw LwsException.conflict("Cannot change resource type via PUT");
                }
                LwsResource updated = storeContent(conn, iri, path, cur.type(), req,
                        cur.created(), now, cur.owner(), cur.publicRead());
                registry.put(conn, updated);
                ev[0] = new ResourceEvent(ActivityKind.UPDATE, iri, cur.type(), webId(principal), now);
                return updated;
            }
            String parentPath = Iris.parentPath(path);
            String parentIri = pathToIri(parentPath);
            LwsResource parent = registry.find(conn, parentIri)
                    .orElseThrow(() -> LwsException.notFound("Parent container does not exist: " + parentIri));
            if (!parent.isContainer()) {
                throw LwsException.conflict("Parent is not a container: " + parentIri);
            }
            authorize(principal, parentIri, AclMode.APPEND);
            ResourceType type = resolveType(req, true, Iris.isContainerPath(path));
            LwsResource child = storeContent(conn, iri, path, type, req,
                    now, now, ownerFor(principal, parent), config.publicReadDefault());
            registry.put(conn, child);
            registry.put(conn, parent.withModified(now));
            created[0] = true;
            ev[0] = new ResourceEvent(ActivityKind.CREATE, iri, type, webId(principal), now);
            return child;
        });
        emit(ev[0]);
        return new PutOutcome(result, created[0]);
    }

    // ----- Patch (SPARQL Update against an RDF resource) -----

    public LwsResource patch(String path, LwsPrincipal principal, byte[] body, String contentType) {
        String ct = contentType == null ? "" : RdfFormats.stripParameters(contentType);
        return switch (ct) {
            case "application/sparql-update" -> patchSparql(path, principal, body);
            case "application/merge-patch+json" -> patchMerge(path, principal, body);
            case "application/json-patch+json" -> patchJsonPatch(path, principal, body);
            default -> throw LwsException.unsupportedMediaType(
                    "PATCH requires application/sparql-update, application/merge-patch+json "
                            + "or application/json-patch+json");
        };
    }

    /** SPARQL 1.1 Update against an RDF resource's graph (LDP/Solid style). */
    private LwsResource patchSparql(String path, LwsPrincipal principal, byte[] body) {
        String iri = pathToIri(path);
        String sparql = new String(body, StandardCharsets.UTF_8);
        // Parse and reject SSRF vectors (LOAD/SERVICE) before opening a transaction.
        UpdateRequest update = SparqlUpdateGuard.check(sparql, config.sparqlUpdateAllowedHosts());
        ResourceEvent[] ev = new ResourceEvent[1];
        LwsResource result = rdf.write(conn -> {
            LwsResource cur = registry.find(conn, iri).orElseThrow(() -> LwsException.notFound(iri));
            if (cur.type() != ResourceType.RDF_SOURCE) {
                throw LwsException.conflict("SPARQL Update PATCH is only supported on RDF resources");
            }
            authorize(principal, iri, AclMode.WRITE);
            // Work on an independent copy: mutating and re-putting a store-backed live model would
            // alias the same named graph (put clears then re-adds, emptying it).
            Model m = ModelFactory.createDefaultModel().add(conn.fetch(iri));
            try {
                UpdateAction.execute(update, m);
            } catch (RuntimeException e) {
                throw LwsException.badRequest("SPARQL Update failed: " + e.getMessage());
            }
            conn.put(iri, m);
            Instant now = now();
            LwsResource nm = new LwsResource(iri, ResourceType.RDF_SOURCE, cur.parentIri(), cur.created(), now,
                    Etags.forModel(m), cur.contentType(), -1, null, cur.owner(), cur.publicRead(), null);
            registry.put(conn, nm);
            ev[0] = new ResourceEvent(ActivityKind.UPDATE, iri, ResourceType.RDF_SOURCE, webId(principal), now);
            return nm;
        });
        emit(ev[0]);
        return result;
    }

    /**
     * JSON Merge Patch (RFC 7386). Applied directly to a JSON (non-RDF) resource's bytes, or — for
     * an RDF resource — to its JSON-LD representation, which is then re-read as RDF.
     */
    private LwsResource patchMerge(String path, LwsPrincipal principal, byte[] body) {
        String iri = pathToIri(path);
        JsonValue patch;
        try {
            patch = JsonMergePatch.read(body);
        } catch (RuntimeException e) {
            throw LwsException.badRequest("Invalid JSON merge patch: " + e.getMessage());
        }
        ResourceEvent[] ev = new ResourceEvent[1];
        LwsResource result = rdf.write(conn -> {
            LwsResource cur = registry.find(conn, iri).orElseThrow(() -> LwsException.notFound(iri));
            if (cur.isContainer()) {
                throw LwsException.conflict("Cannot merge-patch a container");
            }
            authorize(principal, iri, AclMode.WRITE);
            Instant now = now();
            LwsResource nm;
            if (cur.type() == ResourceType.RDF_SOURCE) {
                Model m = ModelFactory.createDefaultModel().add(conn.fetch(iri));
                JsonValue merged = JsonMergePatch.apply(JsonMergePatch.read(RdfIO.write(m, RDFFormat.JSONLD)), patch);
                Model updated;
                try {
                    updated = RdfIO.parse(merged.toString().getBytes(StandardCharsets.UTF_8), Lang.JSONLD, iri);
                } catch (IllegalArgumentException e) {
                    throw LwsException.badRequest("Merge result is not valid JSON-LD: " + e.getMessage());
                }
                conn.put(iri, updated);
                nm = new LwsResource(iri, ResourceType.RDF_SOURCE, cur.parentIri(), cur.created(), now,
                        Etags.forModel(updated), cur.contentType(), -1, null, cur.owner(), cur.publicRead(), null);
            } else {
                if (!RdfFormats.isJson(cur.contentType())) {
                    throw LwsException.unsupportedMediaType("JSON Merge Patch requires a JSON resource");
                }
                byte[] current;
                try (InputStream in = blobs.read(cur.binaryKey())) {
                    current = in.readAllBytes();
                } catch (IOException e) {
                    throw new LwsException(500, "Could not read content: " + e.getMessage(), e);
                }
                byte[] out = JsonMergePatch.apply(JsonMergePatch.read(current), patch)
                        .toString().getBytes(StandardCharsets.UTF_8);
                enforceQuota(conn, out.length, cur.size() >= 0 ? cur.size() : 0);
                BinaryStore.StoredBlob sb;
                try {
                    sb = blobs.write(cur.binaryKey(), new ByteArrayInputStream(out));
                } catch (IOException e) {
                    throw new LwsException(500, "Could not store content: " + e.getMessage(), e);
                }
                nm = new LwsResource(iri, ResourceType.NON_RDF_SOURCE, cur.parentIri(), cur.created(), now,
                        sb.sha256Hex().substring(0, 16), cur.contentType(), sb.size(), cur.binaryKey(),
                        cur.owner(), cur.publicRead(), sb.sha256Hex());
            }
            registry.put(conn, nm);
            ev[0] = new ResourceEvent(ActivityKind.UPDATE, iri, nm.type(), webId(principal), now);
            return nm;
        });
        emit(ev[0]);
        return result;
    }

    /**
     * JSON Patch (RFC 6902). Applied to a JSON (non-RDF) resource's bytes. Not offered for RDF
     * resources (their JSON-LD shape is not a stable pointer target — use SPARQL Update or Merge
     * Patch instead) nor containers.
     */
    private LwsResource patchJsonPatch(String path, LwsPrincipal principal, byte[] body) {
        String iri = pathToIri(path);
        JsonArray patch = JsonPatch.read(body);
        ResourceEvent[] ev = new ResourceEvent[1];
        LwsResource result = rdf.write(conn -> {
            LwsResource cur = registry.find(conn, iri).orElseThrow(() -> LwsException.notFound(iri));
            if (cur.isContainer()) {
                throw LwsException.conflict("Cannot patch a container");
            }
            authorize(principal, iri, AclMode.WRITE);
            if (cur.type() != ResourceType.NON_RDF_SOURCE || !RdfFormats.isJson(cur.contentType())) {
                throw LwsException.unsupportedMediaType("JSON Patch requires a JSON resource");
            }
            byte[] current;
            try (InputStream in = blobs.read(cur.binaryKey())) {
                current = in.readAllBytes();
            } catch (IOException e) {
                throw new LwsException(500, "Could not read content: " + e.getMessage(), e);
            }
            byte[] out = JsonPatch.apply(JsonPatch.readStructure(current), patch)
                    .toString().getBytes(StandardCharsets.UTF_8);
            enforceQuota(conn, out.length, cur.size() >= 0 ? cur.size() : 0);
            Instant now = now();
            BinaryStore.StoredBlob sb;
            try {
                sb = blobs.write(cur.binaryKey(), new ByteArrayInputStream(out));
            } catch (IOException e) {
                throw new LwsException(500, "Could not store content: " + e.getMessage(), e);
            }
            LwsResource nm = new LwsResource(iri, ResourceType.NON_RDF_SOURCE, cur.parentIri(), cur.created(), now,
                    sb.sha256Hex().substring(0, 16), cur.contentType(), sb.size(), cur.binaryKey(),
                    cur.owner(), cur.publicRead(), sb.sha256Hex());
            registry.put(conn, nm);
            ev[0] = new ResourceEvent(ActivityKind.UPDATE, iri, nm.type(), webId(principal), now);
            return nm;
        });
        emit(ev[0]);
        return result;
    }

    // ----- Delete -----

    public void delete(String path, LwsPrincipal principal) {
        delete(path, principal, false);
    }

    /**
     * Delete a resource. A non-empty container is rejected with {@code 409} unless {@code recursive}
     * is requested (the client sent {@code Depth: infinity}, per RFC 4918), in which case the
     * container and all its descendants are removed atomically — the caller must have write access to
     * every resource in the subtree, and a {@code Delete} event is emitted for each.
     */
    public void delete(String path, LwsPrincipal principal, boolean recursive) {
        if (Iris.isRoot(path)) {
            throw LwsException.forbidden("Cannot delete the storage root");
        }
        String iri = pathToIri(path);
        List<ResourceEvent> events = new ArrayList<>();
        rdf.writeDo(conn -> {
            LwsResource cur = registry.find(conn, iri).orElseThrow(() -> LwsException.notFound(iri));
            Instant now = now();
            List<LwsResource> toDelete;
            if (cur.isContainer() && registry.hasChildren(conn, iri)) {
                if (!recursive) {
                    throw LwsException.conflict("Container is not empty: " + iri);
                }
                toDelete = subtree(conn, cur); // descendants first, container last
            } else {
                toDelete = List.of(cur);
            }
            toDelete.forEach(r -> authorize(principal, r.iri(), AclMode.WRITE));
            for (LwsResource r : toDelete) {
                deleteContent(conn, r);
                registry.delete(conn, r.iri());
                events.add(new ResourceEvent(ActivityKind.DELETE, r.iri(), r.type(), webId(principal), now));
            }
            if (cur.parentIri() != null) {
                registry.find(conn, cur.parentIri()).ifPresent(p -> registry.put(conn, p.withModified(now)));
            }
        });
        events.forEach(this::emit);
    }

    private List<LwsResource> subtree(RDFConnection conn, LwsResource container) {
        List<LwsResource> out = new ArrayList<>();
        collectDescendants(conn, container.iri(), out);
        out.add(container);
        return out;
    }

    private void collectDescendants(RDFConnection conn, String containerIri, List<LwsResource> out) {
        for (ResourceRegistry.ChildRef child : registry.children(conn, containerIri)) {
            registry.find(conn, child.iri()).ifPresent(r -> {
                if (r.isContainer()) {
                    collectDescendants(conn, r.iri(), out);
                }
                out.add(r);
            });
        }
    }

    /** Reject a binary write that would push total stored bytes past the configured quota. */
    private void enforceQuota(RDFConnection conn, long newBytes, long replacedBytes) {
        long max = config.quotaMaxBytes();
        if (max <= 0) {
            return; // unlimited
        }
        long projected = registry.totalBytes(conn) - replacedBytes + newBytes;
        if (projected > max) {
            throw LwsException.insufficientStorage("Storage quota exceeded (limit " + max + " bytes)");
        }
    }

    private void deleteContent(RDFConnection conn, LwsResource r) {
        if (r.type() == ResourceType.RDF_SOURCE) {
            conn.delete(r.iri());
        } else if (r.type() == ResourceType.NON_RDF_SOURCE && r.binaryKey() != null) {
            try {
                blobs.delete(r.binaryKey());
            } catch (IOException e) {
                throw new LwsException(500, "Could not delete content: " + e.getMessage(), e);
            }
        }
    }

    // ----- Authorization helpers (also used by the notification subsystem) -----

    public boolean canRead(LwsPrincipal principal, String iri) {
        return authorizer.allows(principal, iri, AclMode.READ);
    }

    public boolean canControl(LwsPrincipal principal, String iri) {
        return authorizer.allows(principal, iri, AclMode.CONTROL);
    }

    public boolean canWrite(LwsPrincipal principal, String iri) {
        return authorizer.allows(principal, iri, AclMode.WRITE);
    }

    public boolean canAppend(LwsPrincipal principal, String iri) {
        return authorizer.allows(principal, iri, AclMode.APPEND);
    }

    /** The HTTP methods permitted on a path, for the {@code Allow} header / OPTIONS. */
    public Set<String> allowedMethods(String path) {
        Optional<LwsResource> meta = stat(path);
        Set<String> allow = new LinkedHashSet<>(List.of("GET", "HEAD", "OPTIONS"));
        if (meta.isEmpty()) {
            allow.add("PUT");
            return allow;
        }
        switch (meta.get().type()) {
            case CONTAINER -> {
                allow.add("POST");
                allow.add("PUT");
                if (!Iris.isRoot(path)) {
                    allow.add("DELETE");
                }
            }
            case RDF_SOURCE -> {
                allow.add("PUT");
                allow.add("PATCH");
                allow.add("DELETE");
            }
            case NON_RDF_SOURCE -> {
                allow.add("PUT");
                if (RdfFormats.isJson(meta.get().contentType())) {
                    allow.add("PATCH"); // JSON Merge Patch
                }
                allow.add("DELETE");
            }
        }
        return allow;
    }

    // ----- internals -----

    private LwsResource storeContent(RDFConnection conn, String iri, String path, ResourceType type,
            WriteRequest req, Instant created, Instant modified, String owner, boolean publicRead) {
        String parentIri = pathToIri(Iris.parentPath(path));
        switch (type) {
            case CONTAINER -> {
                return new LwsResource(iri, ResourceType.CONTAINER, parentIri, created, modified,
                        Etags.of(iri, modified.toString()), null, -1, null, owner, publicRead, null);
            }
            case RDF_SOURCE -> {
                Lang lang = RdfFormats.langForContentType(req.contentType()).orElse(Lang.TURTLE);
                Model m = RdfIO.parse(req.body() == null ? new byte[0] : req.body(), lang, iri);
                conn.put(iri, m);
                String ct = RdfFormats.langForContentType(req.contentType()).isPresent()
                        ? RdfFormats.stripParameters(req.contentType()) : RdfFormats.TURTLE;
                return new LwsResource(iri, ResourceType.RDF_SOURCE, parentIri, created, modified,
                        Etags.forModel(m), ct, -1, null, owner, publicRead, null);
            }
            default -> {
                String key = Iris.binaryKey(path);
                byte[] bytes = req.body() == null ? new byte[0] : req.body();
                long replaced = registry.find(conn, iri).map(LwsResource::size).filter(s -> s >= 0).orElse(0L);
                enforceQuota(conn, bytes.length, replaced);
                BinaryStore.StoredBlob sb;
                try {
                    sb = blobs.write(key, new ByteArrayInputStream(bytes));
                } catch (IOException e) {
                    throw new LwsException(500, "Could not store content: " + e.getMessage(), e);
                }
                String ct = req.contentType() == null ? "application/octet-stream"
                        : RdfFormats.stripParameters(req.contentType());
                return new LwsResource(iri, ResourceType.NON_RDF_SOURCE, parentIri, created, modified,
                        sb.sha256Hex().substring(0, 16), ct, sb.size(), key, owner, publicRead, sb.sha256Hex());
            }
        }
    }

    private ResourceType resolveType(WriteRequest req, boolean isPut, boolean pathIsContainer) {
        if (pathIsContainer || req.typeHint() == TypeHint.CONTAINER) {
            return ResourceType.CONTAINER;
        }
        if (req.typeHint() == TypeHint.NON_RDF_SOURCE) {
            return ResourceType.NON_RDF_SOURCE;
        }
        if (req.typeHint() == TypeHint.RDF_SOURCE) {
            return ResourceType.RDF_SOURCE;
        }
        // AUTO: RDF if the content type is a known RDF serialization, else opaque bytes.
        return RdfFormats.isRdfContentType(req.contentType())
                ? ResourceType.RDF_SOURCE : ResourceType.NON_RDF_SOURCE;
    }

    private String chooseName(RDFConnection conn, String containerPath, String slug, ResourceType type) {
        String base = Iris.sanitizeSlug(slug);
        if (base == null) {
            base = (type == ResourceType.CONTAINER ? "c-" : "r-") + UUID.randomUUID().toString().substring(0, 8);
        }
        String suffix = type == ResourceType.CONTAINER ? "/" : "";
        String candidate = base;
        int n = 1;
        while (registry.exists(conn, pathToIri(containerPath + candidate + suffix))) {
            n++;
            candidate = base + "-" + n;
        }
        return candidate;
    }

    private void authorize(LwsPrincipal principal, String iri, AclMode mode) {
        if (!authorizer.allows(principal, iri, mode)) {
            if (LwsPrincipal.isAnonymous(principal)) {
                throw LwsException.unauthorized("Authentication required (" + mode + ") for " + iri);
            }
            throw LwsException.forbidden("Not authorized (" + mode + ") for " + iri);
        }
    }

    private void emit(ResourceEvent event) {
        if (event == null) {
            return;
        }
        for (ResourceEventListener l : listeners) {
            try {
                l.onResourceEvent(event);
            } catch (RuntimeException e) {
                log.warn("Resource event listener failed for {}: {}", event.iri(), e.toString());
            }
        }
    }

    private static String webId(LwsPrincipal p) {
        return p == null ? null : p.webId();
    }

    private static String ownerFor(LwsPrincipal principal, LwsResource parent) {
        if (principal != null) {
            return principal.webId();
        }
        return parent == null ? null : parent.owner();
    }

    private String pathToIri(String path) {
        return Iris.toIri(config.baseUri(), path);
    }

    private Instant now() {
        return clock.instant();
    }

    public LwsConfiguration config() {
        return config;
    }
}
