package com.ebremer.lws.server.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import jakarta.json.JsonArray;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;
import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdfconnection.RDFConnection;
import org.apache.jena.riot.Lang;
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
     * The result of reading a resource: its metadata, the RDF representation of an RDF <em>data</em>
     * resource, and — for containers — the members this client may see.
     *
     * <p>A container's {@code rdf} is {@code null}: its RDF rendering is one of two representations
     * and is built on demand by {@link ResourceService#containerRepresentation}, because the other
     * one ({@code application/lws+json}) is what almost every request asks for and building both was
     * a full model allocated and discarded per listing (finding M23).
     *
     * <p>{@code children} carries bare {@link ResourceRegistry.ChildRef}s — an IRI and whether it is
     * a container. The listing metadata a page needs comes from
     * {@link ResourceService#describe}, for that page's members only.
     */
    public record ReadResult(LwsResource meta, Model rdf, List<ResourceRegistry.ChildRef> children) {
        /** True if an RDF model is available, i.e. this is an RDF data resource (never a container). */
        public boolean isRdf() {
            return rdf != null;
        }

        /** True if this is a container (its {@link #children} membership is available). */
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
    private final List<ResourceCleanup> cleanups = new CopyOnWriteArrayList<>();
    private volatile DeleteAudience deleteAudience;

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

    /**
     * Register store-local state that must be erased in the same transaction as the resource it
     * belongs to — an ACL graph, a linkset row. Unlike an event listener, a cleanup that fails takes
     * the delete down with it. See {@link ResourceCleanup}.
     */
    public void addDeleteCleanup(ResourceCleanup cleanup) {
        cleanups.add(cleanup);
    }

    /**
     * Supply the decision about who may be told that a resource was deleted. Consulted before the
     * delete transaction opens, because after it the resource's own ACL is gone. See
     * {@link DeleteAudience}.
     */
    public void setDeleteAudience(DeleteAudience audience) {
        this.deleteAudience = audience;
    }

    /** Create the storage root container if it does not yet exist. */
    public void ensureStorageRoot() {
        String iri = config.storageRootIri();
        rdf.writeDo(conn -> {
            if (!registry.exists(conn, iri)) {
                Instant now = now();
                String owner = config.ownerWebIds().stream().findFirst().orElse(null);
                LwsResource root = new LwsResource(iri, ResourceType.CONTAINER, null, now, now,
                        Etags.of(iri, now.toString()), null, -1, null, owner, null);
                registry.put(conn, root);
                log.info("Initialized storage root {}", iri);
            }
        });
    }

    // ----- Reads -----

    /**
     * Whether anything is stored at {@code iri}, with no authorization implied.
     *
     * <p>For callers that need existence and readability as two separate facts. Under Web Access
     * Control they genuinely are two facts: a container's {@code acl:default} makes an absent child
     * readable, so {@code canRead} is not the existence test it happens to be in owner mode.
     */
    public boolean exists(String iri) {
        String path = Iris.toPath(config.baseUri(), iri);
        return path != null && stat(path).isPresent();
    }

    public Optional<LwsResource> stat(String path) {
        String iri = pathToIri(path);
        return rdf.read(conn -> registry.find(conn, iri));
    }

    /**
     * {@link #stat(String)} on a caller-supplied connection, so the lookup takes part in the
     * caller's transaction instead of opening one of its own. {@link LinksetService} needs this to
     * read a resource and its metadata as one consistent state (finding M18).
     */
    public Optional<LwsResource> stat(RDFConnection conn, String path) {
        return registry.find(conn, pathToIri(path));
    }

    /**
     * Read a resource, and for a container the membership the client is allowed to see.
     *
     * <p>The listing is filtered per member — {@code items} and {@code totalItems} reflect only the
     * disclosable view, which lws10-core requires and which is why the filter cannot be pushed into
     * the page window: an exact count of what <em>this</em> client may see needs every member
     * considered. What was reduced instead is what considering one costs (findings M23, M39):
     *
     * <ul>
     *   <li>the whole filter runs in one read transaction rather than opening one per member, which
     *       under owner mode was a fresh connection and registry lookup each time and under WAC an
     *       ACL resolution per ancestor level per member;</li>
     *   <li>it runs over cheap {@code ChildRef}s (an IRI and a flag, one column pair) rather than
     *       full {@code ChildDesc}s, and the media type, size and modified time are fetched only for
     *       the members that reach the page;</li>
     *   <li>where the authorizer's answer cannot vary by resource — a configured owner, open mode, a
     *       public-read storage — the per-member loop is skipped entirely, which is the ordinary
     *       deployment.</li>
     * </ul>
     */
    public ReadResult read(String path, LwsPrincipal principal) {
        String iri = pathToIri(path);
        prepare(principal, iri, AclMode.READ);
        ReadResult loaded = rdf.read(conn -> {
            LwsResource meta = registry.find(conn, iri)
                    .orElseThrow(() -> absent(principal, iri, AclMode.READ));
            authorize(principal, iri, AclMode.READ);
            switch (meta.type()) {
                case CONTAINER -> {
                    return new ReadResult(meta, null, registry.children(conn, meta.iri()));
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
        // The container's entity-tag is the one persisted in the registry (refreshed by `touch`
        // whenever its membership changes), NOT a hash of this rendering. A content-derived tag
        // here could never match the value If-Match is evaluated against, which made conditional
        // PUT/PATCH/DELETE on a container permanently impossible: 428 without a tag, 412 with the
        // one the server had just handed out. Note the listing is authorization-filtered, so this
        // tag is not a validator for a shared cache — container responses are marked no-store.
        if (!loaded.isContainer() || authorizer.allowsEverything(principal, AclMode.READ)) {
            return loaded;
        }
        return new ReadResult(loaded.meta(), null, visibleChildren(principal, loaded.children()));
    }

    /**
     * The members of a container this principal may read.
     *
     * <p>Two steps, in this order, and the order is the whole design.
     *
     * <p><b>Warm, outside any transaction.</b> {@link Authorizer#prepare} resolves whatever the
     * decision would otherwise have to fetch over the network. Web Access Control dereferences
     * {@code acl:agentGroup} membership at an address the requester's own ACL names, and refuses to
     * do so while a unit of work is open (finding H16) — so a decision made inside the transaction
     * resolves group membership from cache alone. The container's own warm-up does not cover its
     * members: it resolves the container's {@code acl:accessTo} authorizations, while members are
     * governed by its {@code acl:default} ones or by ACLs of their own. Without this a member behind
     * an uncached group would vanish from {@code items} <em>and</em> from {@code totalItems}, with a
     * debug line as the only trace. Outside WAC it costs nothing: {@code prepare} defaults to doing
     * nothing at all.
     *
     * <p><b>Then decide, in one transaction.</b> Each {@code allows} used to open its own — a
     * connection, a registry {@code CONSTRUCT} and a commit under owner mode, an ACL resolution per
     * ancestor level under WAC — so a thousand-member container was a thousand transactions, six
     * thousand at WAC depth five, serialized on the request thread (M39). One read transaction now
     * covers the lot, and it is <em>stronger</em> consistency than before: the listing is one
     * snapshot, where it used to be one for the membership and a separate one per decision.
     *
     * <p>Not reached at all when {@link Authorizer#allowsEverything} holds — a configured owner, open
     * mode, a public-read storage — which is the ordinary deployment and turns the sweep into nothing.
     */
    private List<ResourceRegistry.ChildRef> visibleChildren(LwsPrincipal principal,
            List<ResourceRegistry.ChildRef> members) {
        for (ResourceRegistry.ChildRef ref : members) {
            prepare(principal, ref.iri(), AclMode.READ);
        }
        return rdf.read(conn -> members.stream()
                .filter(child -> authorizer.allows(principal, child.iri(), AclMode.READ))
                .toList());
    }

    /**
     * Listing metadata — media type, size, modified — for the members of a container the caller is
     * about to render, in the order given.
     *
     * <p>The caller passes one page's worth. That is the point: the membership is enumerated and
     * authorized in full because {@code totalItems} must reflect the disclosable view, but the
     * per-member <em>metadata</em> is only needed for what is actually being sent (finding M23).
     *
     * <p>The IRIs are not trusted to be members: the query keeps the containment constraint, so a
     * caller that named something else simply gets nothing back for it.
     */
    public List<ResourceRegistry.ChildDesc> describe(String containerIri, List<String> childIris) {
        return rdf.read(conn -> registry.describe(conn, containerIri, childIris));
    }

    /**
     * Bump a container's last-modified <em>and</em> its entity-tag. Both must move together: the
     * tag is derived from the modified instant, so refreshing one without the other leaves a
     * container advertising a tag frozen at creation time no matter how its membership changes.
     */
    private static LwsResource touch(LwsResource container, Instant now) {
        return container.withModified(now).withEtag(Etags.of(container.iri(), now.toString()));
    }

    /** Open the bytes of a non-RDF resource. Caller closes the stream. */
    public InputStream openBinary(LwsResource meta) throws IOException {
        return blobs.read(meta.binaryKey());
    }

    /**
     * Blob keys a write has touched, resolved once the RDF transaction has committed or aborted.
     *
     * <p>The binary store is a plain filesystem and takes no part in the TDB2 transaction, so a
     * blob mutated inside the write callback survives a rollback. Writing every new version to a
     * fresh key (see {@link Iris#newBinaryKey}) and deferring both cleanups until the transaction
     * resolves is what keeps bytes and metadata from diverging: an abort leaves the live blob
     * untouched and drops the staged one; a commit retires the superseded one. The worst outcome of
     * a crash is then an unreferenced blob, never a resource whose metadata describes bytes that
     * are gone.
     */
    private static final class BlobChanges {
        /** Written during the transaction; delete if it aborts. */
        private final List<String> staged = new ArrayList<>();
        /** Replaced or deleted by the transaction; delete once it commits. */
        private final List<String> obsolete = new ArrayList<>();
    }

    private <T> T writeWithBlobs(BlobChanges changes, java.util.function.Function<RDFConnection, T> action) {
        T result;
        try {
            result = rdf.write(action);
        } catch (RuntimeException e) {
            discardBlobs(changes.staged, "uncommitted");
            throw e;
        }
        discardBlobs(changes.obsolete, "superseded");
        return result;
    }

    private void writeDoWithBlobs(BlobChanges changes, java.util.function.Consumer<RDFConnection> action) {
        writeWithBlobs(changes, conn -> {
            action.accept(conn);
            return null;
        });
    }

    /** Best-effort unlink of blobs the store no longer references; a failure only leaks bytes. */
    private void discardBlobs(List<String> keys, String why) {
        for (String key : keys) {
            try {
                blobs.delete(key);
            } catch (IOException | RuntimeException e) {
                log.warn("Could not delete {} blob {}: {}", why, key, e.toString());
            }
        }
    }

    /**
     * The RDF rendering of a container's (already authorization-filtered) membership.
     *
     * <p>Built on demand rather than by {@code read}. Every container GET used to build it, including
     * the overwhelming majority that go on to serve {@code application/lws+json} and throw it away:
     * a 200,000-member listing allocated a 400,000-statement Jena model per request for nothing, and
     * did it for a {@code 304} too (finding M23).
     */
    public Model containerRepresentation(LwsResource container, List<ResourceRegistry.ChildRef> children) {
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
        for (ResourceRegistry.ChildRef child : children) {
            Resource cr = m.createResource(child.iri());
            c.addProperty(LWS.items, cr);
            cr.addProperty(RDF.type, child.container() ? LWS.Container : LWS.DataResource);
        }
        return m;
    }

    // ----- Create (POST into a container) -----

    public LwsResource create(String containerPath, LwsPrincipal principal, WriteRequest req) {
        String containerIri = pathToIri(containerPath);
        prepare(principal, containerIri, AclMode.APPEND);
        ResourceEvent[] ev = new ResourceEvent[1];
        BlobChanges blobChanges = new BlobChanges();
        // The resolved type is a pure function of the request, so a non-RDF body can be written to
        // the binary store out here rather than under the writer lock (finding N2).
        ResourceType requestedType =
                resolveType(req, false, req.slug() != null && req.slug().endsWith("/"));
        LwsResource result = stagedOrDiscarded(blobChanges, () -> {
        StagedBlob staged = stageBody(requestedType, req, blobChanges);
        return writeWithBlobs(blobChanges, conn -> {
            LwsResource container = registry.find(conn, containerIri)
                    .orElseThrow(() -> absent(principal, containerIri, AclMode.APPEND));
            // Authorized first: the 405 below names the target's TYPE, and answering it to a
            // caller who may not read the container told them what is stored there.
            authorize(principal, containerIri, AclMode.APPEND);
            if (!container.isContainer()) {
                // 405, not 409. A data resource does not support POST at all — the method is wrong
                // for this target, which is what 405 says and what the Allow header the servlet
                // attaches then enumerates. 409 says "the request conflicts with the target's
                // current state", i.e. retry when the state changes, and there is no state change
                // that would make POST work here. (PUT keeps its 409 for a non-container *parent*:
                // that genuinely is a state conflict, and creating the parent resolves it.)
                throw new LwsException(405,
                        "POST is not supported on a data resource: " + containerIri);
            }
            ResourceType type = requestedType;
            String name = chooseName(conn, containerPath, req.slug(), type);
            String childPath = containerPath + name + (type == ResourceType.CONTAINER ? "/" : "");
            String childIri = pathToIri(childPath);
            Instant now = now();
            LwsResource child = storeContent(conn, childIri, childPath, type, req,
                    now, now, ownerFor(principal, container), blobChanges, staged);
            registry.put(conn, child);
            registry.put(conn, touch(container, now));
            ev[0] = new ResourceEvent(ActivityKind.CREATE, childIri, type, webId(principal), now);
            return child;
        });
        });
        emit(ev[0]);
        return result;
    }

    // ----- Put (create or replace at an exact IRI) -----

    public PutOutcome put(String path, LwsPrincipal principal, WriteRequest req) {
        return put(path, principal, req, IfMatch.NONE, IfNoneMatch.NONE);
    }

    public PutOutcome put(String path, LwsPrincipal principal, WriteRequest req, IfMatch ifMatch) {
        return put(path, principal, req, ifMatch, IfNoneMatch.NONE);
    }

    /**
     * Create or replace the resource at {@code path}, honouring the client's {@code If-Match} and
     * {@code If-None-Match} preconditions as a compare-and-swap inside the write transaction
     * (findings H23 and L28).
     */
    public PutOutcome put(String path, LwsPrincipal principal, WriteRequest req, IfMatch ifMatch,
            IfNoneMatch ifNoneMatch) {
        if (Iris.isRoot(path)) {
            throw LwsException.badRequest("Cannot PUT the storage root");
        }
        // Before anything else, including the authorization warm-up: a reserved path is refused
        // whether or not the resource exists, so the replace branch cannot write over a legacy
        // resource minted at one of these names before the reservation existed.
        requireCreatablePath(path);
        String iri = pathToIri(path);
        // Which of the two checks below applies depends on whether the resource already exists,
        // and that is only settled inside the transaction. Warming both costs a pair of local ACL
        // lookups and leaves neither branch able to reach for the network once the lock is held.
        prepare(principal, iri, AclMode.WRITE);
        prepare(principal, pathToIri(Iris.parentPath(path)), AclMode.APPEND);
        boolean[] created = {false};
        ResourceEvent[] ev = new ResourceEvent[1];
        BlobChanges blobChanges = new BlobChanges();
        // As in create: resolveType is pure, so the bytes are staged before the lock is taken. The
        // replace branch refuses a type change with 409, so a staged blob is either used or the
        // transaction throws and sweeps it (finding N2).
        ResourceType requestedType = resolveType(req, true, Iris.isContainerPath(path));
        LwsResource result = stagedOrDiscarded(blobChanges, () -> {
        StagedBlob staged = stageBody(requestedType, req, blobChanges);
        return writeWithBlobs(blobChanges, conn -> {
            Optional<LwsResource> existing = registry.find(conn, iri);
            Instant now = now();
            if (existing.isPresent()) {
                LwsResource cur = existing.get();
                authorize(principal, iri, AclMode.WRITE);
                requireConditionalReplace(ifMatch, ifNoneMatch, cur);
                // If-Match first, then If-None-Match: RFC 9110 §13.2.2's evaluation order. Both are
                // compared here, inside the write transaction, for the reason recorded on
                // requirePrecondition.
                requirePrecondition(ifMatch, cur);
                requireNoneMatch(ifNoneMatch, cur);
                // Ordered from "this request contradicts itself" through "it conflicts with what is
                // stored" to "this method cannot do that here": resolveType refuses an interaction
                // model at odds with the IRI's shape (M13) whether or not anything is stored there,
                // so it has to run before the container rule rather than be skipped by it.
                ResourceType reqType = requestedType;
                if (reqType != cur.type()) {
                    throw LwsException.conflict("Cannot change resource type via PUT");
                }
                if (cur.isContainer()) {
                    return replaceContainer(cur, req);
                }
                LwsResource updated = storeContent(conn, iri, path, cur.type(), req,
                        cur.created(), now, cur.owner(), blobChanges, staged);
                registry.put(conn, updated);
                ev[0] = new ResourceEvent(ActivityKind.UPDATE, iri, cur.type(), webId(principal), now);
                return updated;
            }
            // Nothing is here to replace, so a client that named a version does not get to create
            // one: the version it meant to replace was removed in the window between its read and
            // this write, and creating anyway is the lost update If-Match was sent to prevent.
            // An If-None-Match, by contrast, is satisfied by a resource that does not exist —
            // including `*`, whose whole purpose is exactly this case (RFC 9110 §13.1.2).
            requirePrecondition(ifMatch, null);
            String parentPath = Iris.parentPath(path);
            String parentIri = pathToIri(parentPath);
            LwsResource parent = registry.find(conn, parentIri)
                    .orElseThrow(() -> LwsException.notFound("Parent container does not exist: " + parentIri));
            if (!parent.isContainer()) {
                throw LwsException.conflict("Parent is not a container: " + parentIri);
            }
            authorize(principal, parentIri, AclMode.APPEND);
            ResourceType type = requestedType;
            LwsResource child = storeContent(conn, iri, path, type, req,
                    now, now, ownerFor(principal, parent), blobChanges, staged);
            registry.put(conn, child);
            registry.put(conn, touch(parent, now));
            created[0] = true;
            ev[0] = new ResourceEvent(ActivityKind.CREATE, iri, type, webId(principal), now);
            return child;
        });
        });
        emit(ev[0]);
        return new PutOutcome(result, created[0]);
    }

    // ----- Patch (SPARQL Update against an RDF resource) -----

    public LwsResource patch(String path, LwsPrincipal principal, byte[] body, String contentType) {
        return patch(path, principal, body, contentType, IfMatch.NONE);
    }

    /**
     * Patch a resource, honouring the client's {@code If-Match} precondition as a compare-and-swap
     * inside the write transaction (finding H23).
     */
    public LwsResource patch(String path, LwsPrincipal principal, byte[] body, String contentType,
            IfMatch ifMatch) {
        String ct = contentType == null ? "" : RdfFormats.stripParameters(contentType);
        return switch (ct) {
            case "application/sparql-update" -> patchSparql(path, principal, body, ifMatch);
            case "application/merge-patch+json" -> patchMerge(path, principal, body, ifMatch);
            case "application/json-patch+json" -> patchJsonPatch(path, principal, body, ifMatch);
            default -> throw LwsException.unsupportedMediaType(
                    "PATCH requires application/sparql-update, application/merge-patch+json "
                            + "or application/json-patch+json");
        };
    }

    /** SPARQL 1.1 Update against an RDF resource's graph (LDP/Solid style). */
    private LwsResource patchSparql(String path, LwsPrincipal principal, byte[] body, IfMatch ifMatch) {
        String iri = pathToIri(path);
        String sparql = new String(body, StandardCharsets.UTF_8);
        // Parse and reject SSRF vectors (LOAD/SERVICE) before opening a transaction.
        UpdateRequest update = SparqlUpdateGuard.check(sparql, config.sparqlUpdateAllowedHosts());
        prepare(principal, iri, AclMode.WRITE);
        ResourceEvent[] ev = new ResourceEvent[1];
        LwsResource result = rdf.write(conn -> {
            LwsResource cur = registry.find(conn, iri)
                    .orElseThrow(() -> absent(principal, iri, AclMode.WRITE));
            if (cur.type() != ResourceType.RDF_SOURCE) {
                throw LwsException.conflict("SPARQL Update PATCH is only supported on RDF resources");
            }
            authorize(principal, iri, AclMode.WRITE);
            requirePrecondition(ifMatch, cur);
            requireConditionalChange(ifMatch, cur);
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
                    Etags.forModel(m), cur.contentType(), -1, null, cur.owner(), null);
            registry.put(conn, nm);
            ev[0] = new ResourceEvent(ActivityKind.UPDATE, iri, ResourceType.RDF_SOURCE, webId(principal), now);
            return nm;
        });
        emit(ev[0]);
        return result;
    }

    /**
     * JSON Merge Patch (RFC 7386), applied to a JSON (non-RDF) resource's bytes. Not offered for RDF
     * resources or containers — see {@link #requireMergePatchable}.
     */
    private LwsResource patchMerge(String path, LwsPrincipal principal, byte[] body, IfMatch ifMatch) {
        String iri = pathToIri(path);
        JsonValue patch;
        try {
            patch = JsonMergePatch.read(body);
        } catch (RuntimeException e) {
            throw LwsException.badRequest("Invalid JSON merge patch: " + e.getMessage());
        }
        prepare(principal, iri, AclMode.WRITE);
        ResourceEvent[] ev = new ResourceEvent[1];
        BlobChanges blobChanges = new BlobChanges();
        // Read the stored bytes, apply the patch and write the result, all outside the writer lock
        // (finding N2). The snapshot names the version this was computed from, and the transaction
        // below refuses to commit if the stored bytes moved in the meantime.
        //
        // Staged ONLY when the stored resource is already a JSON non-RDF resource. Every refusal
        // this method can make — 404, the container 409, the authorization 401/403, the
        // precondition 412, requireMergePatchable's 415 — is still made inside the transaction in
        // exactly the order it was made before, because doing any of them out here would either
        // change which status a request gets or tell an unauthorized client the media type of a
        // resource it may not read.
        LwsResource snapshot = snapshotIfPatchable(iri, ResourceService::isMergePatchable);
        Prepared prepared = snapshot == null ? new Prepared(null, null)
                : Prepared.of(() -> applyMergePatch(snapshot, patch, blobChanges));
        LwsResource result = stagedOrDiscarded(blobChanges, () ->
        writeWithBlobs(blobChanges, conn -> {
            LwsResource cur = registry.find(conn, iri)
                    .orElseThrow(() -> absent(principal, iri, AclMode.WRITE));
            if (cur.isContainer()) {
                throw LwsException.conflict("Cannot merge-patch a container");
            }
            authorize(principal, iri, AclMode.WRITE);
            requirePrecondition(ifMatch, cur);
            // After requireMergePatchable, not before: "this method cannot be applied here" is a
            // better answer than "you needed a precondition" for a request that could never have
            // worked. The 412 above keeps its existing precedence.
            requireMergePatchable(cur);
            requireConditionalChange(ifMatch, cur);
            Instant now = now();
            // Only now, with the caller authorized and the preconditions met, may the patch's own
            // failure be reported: until here it would have been an answer about stored content.
            StagedBlob patched = prepared.require();
            requireUnchangedContent(cur, snapshot, patched);
            enforceQuota(conn, patched.size(), cur.size() >= 0 ? cur.size() : 0);
            if (cur.binaryKey() != null) {
                blobChanges.obsolete.add(cur.binaryKey());
            }
            LwsResource nm = new LwsResource(iri, ResourceType.NON_RDF_SOURCE, cur.parentIri(), cur.created(), now,
                    patched.sha256Hex().substring(0, 16), cur.contentType(), patched.size(),
                    patched.key(), cur.owner(), patched.sha256Hex());
            registry.put(conn, nm);
            ev[0] = new ResourceEvent(ActivityKind.UPDATE, iri, nm.type(), webId(principal), now);
            return nm;
        }));
        emit(ev[0]);
        return result;
    }

    /**
     * Apply an RFC 7386 merge patch to a stored document and stage the result, outside the lock.
     *
     * <p>The result needs no <em>depth</em> bound — merge patch recurses along the patch, so it can
     * never be deeper than the deeper of its two already-bounded inputs. It does need a <em>size</em>
     * one: a merge patch adds members, so repeated patches grow the stored document linearly with
     * nothing to stop them. Measured: twelve patches under a 200 KB request cap grew a blob to
     * 1.2 MB, and every later read of that resource loads the whole thing into heap.
     */
    private StagedBlob applyMergePatch(LwsResource snapshot, JsonValue patch, BlobChanges changes) {
        JsonValue merged = JsonMergePatch.apply(readStoredJson(readContent(snapshot)), patch);
        JsonLimits.requireBounded(merged, JsonLimits.MAX_NESTING_DEPTH,
                config.maxRequestBytes(), "Patched document would be");
        return stageBytes(merged.toString().getBytes(StandardCharsets.UTF_8), changes);
    }

    /**
     * JSON Merge Patch applies to a JSON resource's bytes, and to nothing else.
     *
     * <p>It used to be offered on RDF resources too, by round-tripping the graph through Jena's
     * JSON-LD. That is not a translation the patch survives. Jena emits a flat node object only for
     * a single-subject model; with two or more it emits {@code {"@graph":[...]}}, and merging the
     * client's members at the top level turns that object into a <em>named graph</em> node. The
     * re-parse then kept only the patch member, on a fresh blank node — measured: a three-triple,
     * two-subject resource came back as one triple — and the server answered {@code 204} with a new
     * entity-tag, so the loss was durable and silent (finding H21). Two subjects is the ordinary
     * shape: a resource and its own {@code #it} fragment.
     *
     * <p>Refused rather than repaired. Making it work would mean patching whichever node object
     * carries the resource's {@code @id}, which asks the client to write its patch against a
     * different document shape depending on how many subjects the resource happens to have — the
     * same reason {@link #patchJsonPatch} already declines RDF, recorded in its own javadoc. SPARQL
     * Update is the defined way to patch RDF here, and it is unaffected.
     */
    private static void requireMergePatchable(LwsResource cur) {
        if (cur.type() != ResourceType.NON_RDF_SOURCE || !RdfFormats.isJson(cur.contentType())) {
            throw LwsException.unsupportedMediaType(
                    "JSON Merge Patch requires a JSON resource; use application/sparql-update to patch RDF");
        }
    }

    /**
     * JSON Patch (RFC 6902). Applied to a JSON (non-RDF) resource's bytes. Not offered for RDF
     * resources (their JSON-LD shape is not a stable pointer target — use SPARQL Update instead)
     * nor containers; Merge Patch is refused on RDF for the same reason, see
     * {@link #requireMergePatchable}.
     */
    private LwsResource patchJsonPatch(String path, LwsPrincipal principal, byte[] body, IfMatch ifMatch) {
        String iri = pathToIri(path);
        JsonArray patch = JsonPatch.read(body);
        prepare(principal, iri, AclMode.WRITE);
        ResourceEvent[] ev = new ResourceEvent[1];
        BlobChanges blobChanges = new BlobChanges();
        // Read, patch and write outside the writer lock, as in patchMerge, and staged on the same
        // condition and for the same reasons (finding N2).
        LwsResource snapshot = snapshotIfPatchable(iri, ResourceService::isMergePatchable);
        Prepared prepared = snapshot == null ? new Prepared(null, null)
                : Prepared.of(() -> applyJsonPatch(snapshot, patch, blobChanges));
        LwsResource result = stagedOrDiscarded(blobChanges, () ->
        writeWithBlobs(blobChanges, conn -> {
            LwsResource cur = registry.find(conn, iri)
                    .orElseThrow(() -> absent(principal, iri, AclMode.WRITE));
            if (cur.isContainer()) {
                throw LwsException.conflict("Cannot patch a container");
            }
            authorize(principal, iri, AclMode.WRITE);
            requirePrecondition(ifMatch, cur);
            if (cur.type() != ResourceType.NON_RDF_SOURCE || !RdfFormats.isJson(cur.contentType())) {
                throw LwsException.unsupportedMediaType("JSON Patch requires a JSON resource");
            }
            requireConditionalChange(ifMatch, cur);
            // As in patchMerge: the patch's own failure is an answer about stored content, so it is
            // raised here rather than where it was computed.
            StagedBlob staged = prepared.require();
            requireUnchangedContent(cur, snapshot, staged);
            enforceQuota(conn, staged.size(), cur.size() >= 0 ? cur.size() : 0);
            Instant now = now();
            if (cur.binaryKey() != null) {
                blobChanges.obsolete.add(cur.binaryKey());
            }
            LwsResource nm = new LwsResource(iri, ResourceType.NON_RDF_SOURCE, cur.parentIri(), cur.created(), now,
                    staged.sha256Hex().substring(0, 16), cur.contentType(), staged.size(),
                    staged.key(), cur.owner(), staged.sha256Hex());
            registry.put(conn, nm);
            ev[0] = new ResourceEvent(ActivityKind.UPDATE, iri, nm.type(), webId(principal), now);
            return nm;
        }));
        emit(ev[0]);
        return result;
    }

    // ----- Delete -----

    public void delete(String path, LwsPrincipal principal) {
        delete(path, principal, false, IfMatch.NONE);
    }

    /**
     * Delete a resource. A non-empty container is rejected with {@code 409} unless {@code recursive}
     * is requested (the client sent {@code Depth: infinity}, per RFC 4918), in which case the
     * container and all its descendants are removed atomically — the caller must have write access to
     * every resource in the subtree, and a {@code Delete} event is emitted for each.
     */
    public void delete(String path, LwsPrincipal principal, boolean recursive) {
        delete(path, principal, recursive, IfMatch.NONE);
    }

    /**
     * Delete a resource, honouring the client's {@code If-Match} precondition as a compare-and-swap
     * inside the write transaction (finding H23). The precondition names the target of the request;
     * a recursive delete does not condition on each descendant, which has no tag the client saw.
     */
    public void delete(String path, LwsPrincipal principal, boolean recursive, IfMatch ifMatch) {
        if (Iris.isRoot(path)) {
            throw LwsException.forbidden("Cannot delete the storage root");
        }
        String iri = pathToIri(path);
        // AclMode.DELETE, not WRITE, on all four sites in this method — the warm-up, the target's
        // authorization, each descendant's warm-up and each descendant's authorization. They must
        // move together: `prepare` warms the cache keyed by the mode it is given, so warming WRITE
        // and deciding DELETE would leave a WAC agentGroup unresolved inside the transaction and
        // fail the decision closed (finding M8, and H16's reason for `prepare` existing at all).
        prepare(principal, iri, AclMode.DELETE);
        // A recursive delete authorizes every descendant, and the subtree is only known from inside
        // the transaction. Enumerate it once in a read transaction, which takes no writer lock, so
        // each member's authorization inputs are resolved before the write transaction opens. The
        // authoritative per-member check below is unchanged; a member that appears in the window
        // between the two simply gets no warm-up.
        List<String> members = recursive
                ? rdf.read(conn -> registry.find(conn, iri)
                        .filter(LwsResource::isContainer)
                        .map(c -> subtree(conn, c).stream().map(LwsResource::iri).toList())
                        .orElse(List.of(iri)))
                : List.of(iri);
        if (recursive) {
            members.forEach(member -> prepare(principal, member, AclMode.DELETE));
        }
        // Ask now, while each resource and its own ACL still exist, who may be told it is gone.
        // After the transaction commits the ACL has gone with it (H24), so the same question then
        // resolves through container inheritance and answers "whoever can read the parent" — which
        // is how the existence of a private child leaked to a subscriber of its container (H19).
        Map<String, Set<String>> audience = captureDeleteAudience(members);
        List<ResourceEvent> events = new ArrayList<>();
        BlobChanges blobChanges = new BlobChanges();
        writeDoWithBlobs(blobChanges, conn -> {
            LwsResource cur = registry.find(conn, iri)
                    .orElseThrow(() -> absent(principal, iri, AclMode.DELETE));
            // Authorization first, then the precondition, then the method's own semantics: a client
            // that may not write here is refused whatever tag it holds (RFC 9110 section 13.2.2
            // ignores preconditions on a request that would have failed anyway), and a stale tag on
            // a non-empty container is 412 rather than 409.
            authorize(principal, iri, AclMode.DELETE);
            requirePrecondition(ifMatch, cur);
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
            // Every descendant must be deletable too; the named target was authorized above.
            toDelete.stream()
                    .filter(r -> !r.iri().equals(iri))
                    .forEach(r -> authorize(principal, r.iri(), AclMode.DELETE));
            for (LwsResource r : toDelete) {
                deleteContent(conn, r, blobChanges);
                registry.delete(conn, r.iri());
                // Here, not in the post-commit fan-out below: a resource's ACL and its linkset are
                // part of what the resource is, so erasing them has to commit or roll back with the
                // delete itself rather than be attempted afterwards and logged if it fails (H24).
                for (ResourceCleanup cleanup : cleanups) {
                    cleanup.onDelete(conn, r.iri());
                }
                // A member with no captured audience tells nobody: the fail-closed direction, and
                // the one the old `parent == null ||` fallback got backwards.
                events.add(new ResourceEvent(ActivityKind.DELETE, r.iri(), r.type(), webId(principal), now,
                        audience.getOrDefault(r.iri(), Set.of())));
            }
            if (cur.parentIri() != null) {
                registry.find(conn, cur.parentIri()).ifPresent(p -> registry.put(conn, touch(p, now)));
            }
        });
        events.forEach(this::emit);
    }

    /** Who may be told about each of these resources, asked before any of them is removed. */
    private Map<String, Set<String>> captureDeleteAudience(List<String> iris) {
        DeleteAudience hook = deleteAudience;
        if (hook == null) {
            return Map.of();
        }
        Map<String, Set<String>> out = new LinkedHashMap<>();
        for (String member : iris) {
            out.put(member, hook.subscribersAllowedToKnow(member));
        }
        return out;
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

    /**
     * Parse a stored JSON blob so it can be patched.
     *
     * <p>The depth guard inside these readers refuses a document nested past the bound — but for a
     * <em>stored</em> blob that is not the client's fault: {@code PUT} stores bytes without ever
     * parsing them, so the server accepted this document and is now declining to patch it. Reported
     * as a conflict with the stored state, which a {@code PUT} resolves, rather than as a malformed
     * request, which is what the reader's own {@code 400} would say.
     */
    private static JsonValue readStoredJson(byte[] stored) {
        try {
            return JsonMergePatch.read(stored);
        } catch (LwsException e) {
            throw LwsException.conflict("The stored document cannot be patched ("
                    + e.getMessage() + "); replace it with PUT");
        }
    }

    /** The {@link JsonStructure} form of {@link #readStoredJson}, for RFC 6902 JSON Patch. */
    private static JsonStructure readStoredStructure(byte[] stored) {
        try {
            return JsonPatch.readStructure(stored);
        } catch (LwsException e) {
            throw LwsException.conflict("The stored document cannot be patched ("
                    + e.getMessage() + "); replace it with PUT");
        }
    }

    /**
     * The stored version a patch may be computed from ahead of the transaction, or {@code null} if
     * there is nothing here that a patch could be applied to.
     *
     * <p>Deliberately raises nothing. Every refusal stays inside the write transaction, in the order
     * it was already made: raising a {@code 404} or a {@code 415} out here would reorder it ahead of
     * the authorization check and tell an unauthorized client whether a resource exists and what
     * media type it has.
     */
    private LwsResource snapshotIfPatchable(String iri, java.util.function.Predicate<LwsResource> ok) {
        LwsResource meta = rdf.read(conn -> registry.find(conn, iri)).orElse(null);
        return meta != null && ok.test(meta) ? meta : null;
    }

    /** Apply an RFC 6902 patch to a stored document and stage the result, all outside the lock. */
    private StagedBlob applyJsonPatch(LwsResource snapshot, JsonArray patch, BlobChanges blobChanges) {
        JsonStructure computed = JsonPatch.apply(readStoredStructure(readContent(snapshot)), patch);
        // Bound the RESULT, not just the two inputs. RFC 6902 addresses by JSON Pointer, so a
        // two-level patch body can plant a value at a position sixty levels down and the merged
        // document is deeper than either input. Without this the next PATCH of this resource is
        // refused by readStructure's own guard, with a message blaming a patch three tokens long
        // for a document the server itself stored (finding N5, blob half).
        JsonLimits.requireBounded(computed, JsonLimits.MAX_NESTING_DEPTH,
                config.maxRequestBytes(), "Patched document would be");
        return stageBytes(computed.toString().getBytes(StandardCharsets.UTF_8), blobChanges);
    }

    /** Whether a stored resource is one a JSON patch can be applied to at all. */
    private static boolean isMergePatchable(LwsResource meta) {
        return meta.type() == ResourceType.NON_RDF_SOURCE && RdfFormats.isJson(meta.contentType());
    }

    /**
     * The stored bytes of a non-RDF resource, read outside the writer lock.
     *
     * <p>Reading outside the transaction means the key can be retired between the lookup and the
     * open: a concurrent write commits and unlinks the version this was about to read. That is not a
     * server fault, it is exactly the race {@link #requireUnchangedContent} exists to report, so it
     * answers the same {@code 412}. Any other I/O failure keeps its {@code 500} but loses the
     * message: it carried the data directory's absolute path and the internal blob key straight to
     * the client, because the servlet renders an {@code LwsException}'s message verbatim.
     */
    private byte[] readContent(LwsResource meta) {
        if (meta.binaryKey() == null) {
            return new byte[0];
        }
        try (InputStream in = blobs.read(meta.binaryKey())) {
            return in.readAllBytes();
        } catch (java.nio.file.NoSuchFileException e) {
            throw LwsException.preconditionFailed(
                    "The resource changed while the patch was being applied");
        } catch (IOException e) {
            log.warn("Could not read the content of {}: {}", meta.iri(), e.toString());
            throw new LwsException(500, "Could not read content", e);
        }
    }

    /**
     * Refuse to commit a patch that was computed from bytes which are no longer the stored ones.
     *
     * <p>A patch is a read-modify-write, and moving the read out of the transaction (finding N2)
     * would reintroduce the lost update Batch G closed unless the write re-checks what it was
     * computed from. The check is on {@code binaryKey} identity rather than on the entity-tag,
     * because every write mints a fresh key, so an unchanged key is proof that nothing intervened.
     * An entity-tag is not proof of the same thing: it is a 64-bit prefix of a content hash, and a
     * precondition of {@code *} is satisfied by any version at all, so a client sending that would
     * have had no protection whatsoever.
     *
     * <p>{@code 412} rather than a silent retry: a {@code PATCH} here must already carry a
     * precondition, so the client has the machinery to re-read and try again, and this is exactly
     * the answer that says the state it based the request on is gone.
     */
    private static void requireUnchangedContent(LwsResource current, LwsResource snapshot,
            StagedBlob staged) {
        // staged == null means the resource was not patchable when it was read a moment ago and is
        // patchable now, so it was replaced in between. Same answer, same reason.
        if (staged == null || snapshot == null
                || !java.util.Objects.equals(current.binaryKey(), snapshot.binaryKey())) {
            throw LwsException.preconditionFailed(
                    "The resource changed while the patch was being applied");
        }
    }

    /** Bytes already written to the binary store under a key nothing references yet. */
    private record StagedBlob(String key, long size, String sha256Hex) {
    }

    /**
     * Write a non-RDF body to the binary store <em>before</em> the write transaction opens.
     *
     * <p>The store admits one writer for the whole storage, so streaming up to
     * {@code lws.max-request-bytes} — 64 MiB by default — into the binary store from inside the
     * write callback made every other write in the server wait for a filesystem copy, and on an
     * NFS or SMB data directory for network I/O (finding N2). None of it needs the lock: the key is
     * freshly minted so no reader can reach it, and {@link BlobChanges} already exists to unlink a
     * staged key if the transaction aborts.
     *
     * <p>Staged only when the request's own type resolves to a non-RDF resource, which is a pure
     * function of the request and so is knowable out here. That matters for more than cost: it is
     * what guarantees the staged bytes are either used by the transaction or the transaction throws.
     * A PUT whose resolved type disagrees with what is stored is a 409, and a container body is
     * refused — both exceptions, both of which sweep {@code staged}. So there is no branch that
     * commits while leaving a staged blob unreferenced, and no need to track one.
     */
    private StagedBlob stageBody(ResourceType type, WriteRequest req, BlobChanges blobChanges) {
        if (type != ResourceType.NON_RDF_SOURCE) {
            return null;
        }
        byte[] bytes = req.body() == null ? new byte[0] : req.body();
        return stageBytes(bytes, blobChanges);
    }

    /**
     * Write {@code bytes} under a fresh key, registering it <em>before</em> returning so that any
     * later failure unlinks it.
     *
     * <p>The registration used to happen at the far end, inside the transaction and after the
     * authorization check, which meant every refusal in between — a denial, a stale {@code If-Match},
     * a type-change conflict, a quota rejection — left the bytes on disk with nothing referencing
     * them and nothing to sweep them. Measured: five conditional {@code PUT}s refused {@code 412}
     * grew the store by 10 MB, and a {@code 507} deposited the very bytes the quota had just
     * refused, invisibly to the quota's own accounting. See {@link #stagedOrDiscarded}.
     */
    private StagedBlob stageBytes(byte[] bytes, BlobChanges blobChanges) {
        String key = Iris.newBinaryKey(); // fresh, so this write cannot touch bytes a reader holds
        BinaryStore.StoredBlob sb;
        try {
            sb = blobs.write(key, new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            throw new LwsException(500, "Could not store content: " + e.getMessage(), e);
        }
        blobChanges.staged.add(key);
        return new StagedBlob(key, sb.size(), sb.sha256Hex());
    }

    /**
     * Run a write that stages bytes before its transaction opens, unlinking them unless it commits.
     *
     * <p>{@link #writeWithBlobs} only covers the transaction itself. Everything a write does
     * <em>before</em> that — staging the body, reading a stored document, applying a patch — can
     * fail too, and until this existed those failures were the ones that leaked.
     */
    private <T> T stagedOrDiscarded(BlobChanges changes, java.util.function.Supplier<T> work) {
        try {
            return work.get();
        } catch (RuntimeException | Error e) {
            discardBlobs(changes.staged, "uncommitted");
            changes.staged.clear(); // so writeWithBlobs does not try the same keys again
            throw e;
        }
    }

    /**
     * The outcome of work done before the write transaction: staged bytes, or the failure that
     * computing them produced.
     *
     * <p>Carrying the failure rather than throwing it is the point. Applying a client's patch to a
     * stored document is a computation <em>over content</em>, and doing it ahead of the transaction
     * — which is where the authorization check lives — let its failures answer questions about a
     * document the caller may not read. An RFC 6902 {@code test} operation is a value comparison, so
     * "did this patch apply" is a read primitive: measured, a caller holding only Append on a
     * container could extract members of a child it had no access to, one {@code test} at a time.
     * The failure is therefore held and re-thrown inside the transaction, after {@code authorize},
     * in the position it would have occupied all along.
     */
    private record Prepared(StagedBlob blob, RuntimeException failure) {

        static Prepared of(java.util.function.Supplier<StagedBlob> work) {
            try {
                return new Prepared(work.get(), null);
            } catch (LwsException e) {
                return new Prepared(null, e);
            }
        }

        /** Raise whatever computing the bytes produced. Call only after authorizing. */
        StagedBlob require() {
            if (failure != null) {
                throw failure;
            }
            return blob;
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

    private void deleteContent(RDFConnection conn, LwsResource r, BlobChanges blobChanges) {
        if (r.type() == ResourceType.RDF_SOURCE) {
            conn.delete(r.iri()); // part of the transaction, so it rolls back with it
        } else if (r.type() == ResourceType.NON_RDF_SOURCE && r.binaryKey() != null) {
            // Unlinked only once the delete has committed: a rollback here previously left the
            // bytes gone while every registry entry survived, so each subsequent GET 500'd.
            blobChanges.obsolete.add(r.binaryKey());
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

    /**
     * Whether {@code principal} may remove {@code iri}. Distinct from {@link #canWrite}: an access
     * grant naming only the ODRL action {@code modify} authorizes the one and not the other
     * (finding M8). Under WAC and under owner-based authorization the two answers coincide.
     */
    public boolean canDelete(LwsPrincipal principal, String iri) {
        return authorizer.allows(principal, iri, AclMode.DELETE);
    }

    /**
     * The HTTP methods permitted on a path, for the {@code Allow} header and for OPTIONS.
     *
     * <p>Takes a principal because the answer discloses the resource's <em>type</em> — a container
     * accepts POST, an RDF source accepts PATCH — and computing it from the stored resource for a
     * caller who may not read it handed out exactly what {@link #denied} exists to withhold. A
     * principal without Read is answered as though nothing were stored there.
     */
    public Set<String> allowedMethods(String path, LwsPrincipal principal) {
        Optional<LwsResource> meta = stat(path);
        if (meta.isPresent() && config.maskForbiddenAsNotFound()
                && !canRead(principal, pathToIri(path))) {
            meta = Optional.empty();
        }
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

    /**
     * Write one resource's content inside the transaction that registers it.
     *
     * <p>{@code staged} carries the bytes of a non-RDF body, already on disk under a fresh key,
     * written before the transaction opened. It is null for every other type. See
     * {@link #stageBody}.
     */
    private LwsResource storeContent(RDFConnection conn, String iri, String path, ResourceType type,
            WriteRequest req, Instant created, Instant modified, String owner,
            BlobChanges blobChanges, StagedBlob staged) {
        String parentIri = pathToIri(Iris.parentPath(path));
        switch (type) {
            case CONTAINER -> {
                requireNoContainerBody(req, iri);
                return new LwsResource(iri, ResourceType.CONTAINER, parentIri, created, modified,
                        Etags.of(iri, modified.toString()), null, -1, null, owner, null);
            }
            case RDF_SOURCE -> {
                Lang lang = RdfFormats.langForContentType(req.contentType()).orElse(Lang.TURTLE);
                Model m = RdfIO.parse(req.body() == null ? new byte[0] : req.body(), lang, iri);
                conn.put(iri, m);
                String ct = RdfFormats.langForContentType(req.contentType()).isPresent()
                        ? RdfFormats.stripParameters(req.contentType()) : RdfFormats.TURTLE;
                return new LwsResource(iri, ResourceType.RDF_SOURCE, parentIri, created, modified,
                        Etags.forModel(m), ct, -1, null, owner, null);
            }
            default -> {
                Optional<LwsResource> existing = registry.find(conn, iri);
                long replaced = existing.map(LwsResource::size).filter(sz -> sz >= 0).orElse(0L);
                // The quota READ stays in here — only inside the write transaction is it a
                // compare-and-swap — but it needs nothing except the byte length, which staging
                // already knows. The bytes themselves were written to disk before the transaction
                // opened (finding N2).
                enforceQuota(conn, staged.size(), replaced);
                existing.map(LwsResource::binaryKey).filter(java.util.Objects::nonNull)
                        .ifPresent(blobChanges.obsolete::add);
                String ct = req.contentType() == null ? "application/octet-stream"
                        : RdfFormats.stripParameters(req.contentType());
                return new LwsResource(iri, ResourceType.NON_RDF_SOURCE, parentIri, created, modified,
                        staged.sha256Hex().substring(0, 16), ct, staged.size(), staged.key(), owner,
                        staged.sha256Hex());
            }
        }
    }

    /**
     * PUT over an existing container.
     *
     * <p>A container's representation <em>is</em> its membership, which the server derives from the
     * registry; there is nowhere for a client's triples to go and nothing for them to replace. The
     * body used to be discarded in silence and the container re-registered with a fresh
     * {@code modified} and entity-tag, so the answer to "store this" was {@code 204} plus every sign
     * of a new version having been stored (finding M14).
     *
     * <p>So: a body is refused, and a bodiless PUT — the idempotent "make sure this container
     * exists" — succeeds while changing nothing at all. Bumping the tag for a write that stored
     * nothing is not harmless: a client holding the tag it had just read would find its next
     * conditional write refused with {@code 412} for a change that never happened.
     */
    private static LwsResource replaceContainer(LwsResource cur, WriteRequest req) {
        requireNoContainerBody(req, cur.iri());
        return cur;
    }

    /**
     * A container is not somewhere a client's triples can go, whether it is being created or
     * replaced.
     *
     * <p>Stated on the container rather than on one branch of {@code put}, because the first cut of
     * this rule guarded only the replace branch and creating a container went on discarding the body
     * and answering {@code 201} with a fresh entity-tag — the same defect one branch over. All three
     * create routes (PUT at a new IRI, POST with a container hint, POST with a {@code /}-terminated
     * Slug) reach {@link #storeContent}, so the check sits there as well.
     */
    private static void requireNoContainerBody(WriteRequest req, String iri) {
        if (req.body() != null && req.body().length > 0) {
            throw LwsException.conflict(
                    "A container's representation is its membership and is managed by this storage; "
                            + "POST or PUT the members instead: " + iri);
        }
    }

    private ResourceType resolveType(WriteRequest req, boolean isPut, boolean pathIsContainer) {
        // A name's shape and an explicit interaction model can contradict each other, and picking
        // one silently is how a CONTAINER ends up registered at a slash-less IRI. Nothing downstream
        // survives that: `Iris.parentPath` reads the string, not the registered type, so `create`
        // composes "/x/foo" + "bar" = "/x/foobar", whose parent recomputes to "/x/" — children land
        // in the wrong container and the one the client asked for lists nothing (finding M13).
        //
        // The trailing-slash half applies to POST too, because `create` derives `pathIsContainer`
        // from the raw Slug: `Slug: pics/` with `Link: rel="type" NonRDFSource` had the slash win
        // silently and the uploaded bytes thrown away.
        if (req.typeHint() != TypeHint.AUTO) {
            boolean hintIsContainer = req.typeHint() == TypeHint.CONTAINER;
            // A trailing slash always means container, so a non-container hint contradicts it on
            // either method.
            if (pathIsContainer && !hintIsContainer) {
                throw LwsException.badRequest(
                        "A name ending in '/' names a container, so it cannot be created as "
                                + req.typeHint());
            }
            // The absence of a slash only contradicts a container hint on PUT, where the client
            // named the final IRI. On POST the Slug is a name, not an address — `create` appends
            // the slash itself from the type resolved here — so `Slug: notes` with a container hint
            // is the ordinary way to POST a container, not a contradiction.
            if (isPut && hintIsContainer && !pathIsContainer) {
                throw LwsException.badRequest("A container IRI must end in '/'");
            }
        }
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

    /**
     * How many {@code name-2}, {@code name-3}, … probes a colliding {@code Slug} gets before the
     * server stops counting and picks a random suffix instead.
     */
    private static final int MAX_SEQUENTIAL_NAME_PROBES = 8;

    /** How many random suffixes are tried after that; a collision here is already astronomically rare. */
    private static final int MAX_RANDOM_NAME_PROBES = 4;

    /**
     * Choose a free child name for a {@code Slug}, in a bounded number of probes.
     *
     * <p>The de-duplication used to be an <em>uncapped</em> linear scan — {@code name}, {@code name-2},
     * {@code name-3}, … — issuing one {@code ASK} per iteration, <b>inside the global write
     * transaction</b>. The store admits a single writer, so the Nth POST of a repeated {@code Slug}
     * held that writer for N queries while every other write in the storage waited, and the sequence
     * as a whole is quadratic: ten thousand POSTs of the same {@code Slug} cost about fifty million
     * {@code ASK}s (finding M15). Nothing bounded it but the client's patience.
     *
     * <p>So the sequence is capped and then abandoned for a random suffix, which collides only by
     * accident rather than by construction. The result is at most
     * {@code MAX_SEQUENTIAL_NAME_PROBES + MAX_RANDOM_NAME_PROBES} probes per request regardless of how
     * many resources share the name. The trade is that the ninth {@code Slug: report} becomes
     * {@code report-a3f19c04} rather than {@code report-9}; {@code Location} names it either way.
     *
     * <p>The random suffix is still probed rather than trusted, because {@link ResourceRegistry#put}
     * is a delete-then-load: writing over a name that turned out to be taken would replace another
     * resource's metadata rather than fail. And the composed path is re-checked against the reserved
     * namespace at the end, so the fallback cannot land somewhere {@link #requireCreatablePath} would
     * have refused.
     */
    private String chooseName(RDFConnection conn, String containerPath, String slug, ResourceType type) {
        String base = Iris.sanitizeSlug(slug);
        if (base == null) {
            base = (type == ResourceType.CONTAINER ? "c-" : "r-") + UUID.randomUUID().toString().substring(0, 8);
        }
        String suffix = type == ResourceType.CONTAINER ? "/" : "";
        // Checked here, on the composed path, for three reasons: sanitizing can *create* a reserved
        // name (Slug "x.acl-" trims to "x.acl"), the absolute reservations are invisible to a
        // segment-only test (Slug "app" at the root composes "/app"), and the de-duplication loop
        // below would otherwise turn a reserved name into the legal-but-baffling "x.acl-2".
        requireCreatablePath(containerPath + base + suffix);
        String candidate = base;
        for (int n = 2; n <= MAX_SEQUENTIAL_NAME_PROBES
                && registry.exists(conn, pathToIri(containerPath + candidate + suffix)); n++) {
            candidate = base + "-" + n;
        }
        for (int attempt = 0; attempt < MAX_RANDOM_NAME_PROBES
                && registry.exists(conn, pathToIri(containerPath + candidate + suffix)); attempt++) {
            candidate = base + "-" + UUID.randomUUID().toString().substring(0, 8);
        }
        String chosen = containerPath + candidate + suffix;
        requireCreatablePath(chosen);
        if (registry.exists(conn, pathToIri(chosen))) {
            throw LwsException.conflict("Could not find a free name under " + containerPath
                    + " for the requested Slug; choose another");
        }
        return candidate;
    }

    /**
     * Resolve an authorization decision's remote inputs before the transaction that will make it
     * opens. The store admits a single writer, so an authorizer that dereferences a document over
     * the network from inside a write callback — Web Access Control does exactly that for
     * {@code acl:agentGroup}, at an address the requester's own ACL names — holds that writer lock
     * for the duration, stalling every other write in the storage.
     *
     * <p>Only the inputs move: {@link #authorize} stays inside the transaction and stays
     * authoritative, so it still sees an ACL tightened or a grant revoked in the meantime. This is
     * the same reasoning the container child-filter in {@link #read} applies, made explicit.
     *
     * <p>Advisory throughout: it makes no decision, raises nothing, and cannot change a status code
     * — a warm-up for a resource that turns out not to exist simply achieves nothing, leaving the
     * {@code 404} to be raised inside the transaction exactly as before.
     */
    private void prepare(LwsPrincipal principal, String iri, AclMode mode) {
        authorizer.prepare(principal, iri, mode);
    }

    /**
     * Refuse a path whose name belongs to something else — an ACL or linkset address, the system
     * prefix, or the console and login trees. The router already diverts every one of these, so a
     * resource created there is at best permanently unreachable and at worst, before the ACL graphs
     * moved out of the public IRI space, the access-control graph itself.
     *
     * <p>Refused rather than quietly renamed. Sanitizing the name away would answer a request a
     * security control just denied with {@code 201 Created} and a {@code Location} header pointing
     * somewhere the client never asked for — and a client that trusts {@code Location} would then
     * write to it.
     *
     * <p>Not applied to {@link #ensureStorageRoot}, which writes a fixed server-owned path directly
     * to the registry rather than through a client-named create.
     */
    private void requireCreatablePath(String path) {
        if (config.isReservedPath(path)) {
            throw LwsException.conflict(
                    "The name " + path + " is reserved by this storage; choose another");
        }
    }

    private void authorize(LwsPrincipal principal, String iri, AclMode mode) {
        if (!authorizer.allows(principal, iri, mode)) {
            throw denied(principal, iri, mode);
        }
    }

    /**
     * The refusal for a principal who may not do {@code mode} to {@code iri}.
     *
     * <p>Existence is resolved before authorization on every path here, so a client that may not
     * read a resource could tell one that exists from one that does not: {@code 403} meant "it is
     * there", {@code 404} meant "it is not". That is an existence oracle over the whole storage,
     * and it needs no credential worth having — it discloses names, and under WAC a name is often
     * the interesting part.
     *
     * <p>So a principal without Read is told {@code 404} whether or not the resource is there. The
     * masking is deliberately keyed on <em>Read</em> rather than on the mode being refused: a client
     * who may read a resource but not write it already knows it exists, and answering {@code 404}
     * to their {@code PUT} would be a lie that helps nobody.
     *
     * <p><strong>Anonymous still gets {@code 401}</strong>, and that is not an oversight. An
     * unauthenticated client has to be told that authenticating is what it is missing — RFC 9110's
     * challenge, and the whole Solid discovery story, depend on it. Masking it as {@code 404} would
     * make an unauthenticated client unable to discover that anything is there to sign in for.
     *
     * <p><strong>What this does not close, stated plainly.</strong> Under WAC the anonymous
     * {@code 401}/{@code 404} split still discriminates, and no amount of status-code masking can
     * fix it: WAC resolves a decision from the target's own ACL graph and falls back to the nearest
     * ancestor's {@code acl:default}, so a path with its own ACL answers differently from one
     * without — and under WAC having an own ACL is very nearly the same fact as existing. Closing
     * that means changing the authorization model, not the status code. The masking here removes the
     * oracle for every authenticated client and in owner mode removes it entirely.
     */
    private LwsException denied(LwsPrincipal principal, String iri, AclMode mode) {
        if (LwsPrincipal.isAnonymous(principal)) {
            return LwsException.unauthorized("Authentication required (" + mode + ") for " + iri);
        }
        if (config.maskForbiddenAsNotFound()
                && (mode == AclMode.READ || !authorizer.allows(principal, iri, AclMode.READ))) {
            return LwsException.notFound(iri);
        }
        return LwsException.forbidden("Not authorized (" + mode + ") for " + iri);
    }

    /**
     * The refusal for a request whose target is not there.
     *
     * <p>A bare {@code 404} closes only half the oracle. {@link #denied} stops an authenticated
     * non-reader from telling a hidden resource from an absent one — but an <em>anonymous</em>
     * client got {@code 401} for the hidden one and {@code 404} for the absent one, which is the
     * same disclosure and needs no credential at all to exploit. So when the principal could not
     * have read the resource had it existed, the absent case is answered exactly as the hidden case
     * is: {@code 401} for anonymous, {@code 404} for anyone else.
     *
     * <p>Where the principal <em>may</em> read — open mode, a public-read storage, a container they
     * have access to — this is a plain {@code 404}, because there is nothing to hide from them.
     */
    private LwsException absent(LwsPrincipal principal, String iri, AclMode mode) {
        if (!config.maskForbiddenAsNotFound()) {
            return LwsException.notFound(iri);
        }
        // NOT authorizer.allows(principal, iri, READ). An absent resource has no registry entry, and
        // OwnerAuthorizer answers false for any IRI that has none — so asking that question would
        // mask every 404 in the server, including in open mode, where there is nothing to hide. It
        // is the same trap H16 recorded when it rejected hoisting authorization above the existence
        // check. Two questions that ARE meaningful about a resource that is not there:
        if (authorizer.allowsEverything(principal, AclMode.READ)) {
            return LwsException.notFound(iri);
        }
        // ...and whether they may read the container it would have been in. A client who can list
        // the parent can already see that this child is not among its members, so telling them
        // plainly costs nothing; a client who cannot learns nothing either way.
        String path = Iris.toPath(config.baseUri(), iri);
        String parentPath = path == null ? null : Iris.parentPath(path);
        if (parentPath != null
                && authorizer.allows(principal, pathToIri(parentPath), AclMode.READ)) {
            return LwsException.notFound(iri);
        }
        return denied(principal, iri, mode);
    }

    /** The refusal a caller outside this class should raise for a target that is not there. */
    public LwsException absenceFor(LwsPrincipal principal, String iri, AclMode mode) {
        return absent(principal, iri, mode);
    }

    /** The refusal a caller outside this class should raise for an unauthorized principal. */
    public LwsException refusalFor(LwsPrincipal principal, String iri, AclMode mode) {
        return denied(principal, iri, mode);
    }

    /**
     * Replacing something that already exists has to name the version it replaces.
     *
     * <p>lws10-core requires it of {@code PUT}, and the rule used to be enforced only in
     * {@code LwsResourceServlet} — which meant it governed the HTTP API and nothing else. The Wicket
     * console calls this service directly and was therefore exempt: two users editing the same
     * resource each read it, each saved, and the second silently discarded the first while the UI
     * reported "Saved." (finding M20). A rule only one of two entry points enforces is not a rule,
     * so it lives on the object both of them go through.
     *
     * <p>{@code core} still holds no servlet or framework type; a status code is not one, and
     * {@link LwsException} has carried them from here since the beginning. The servlet keeps its own
     * copy of this check purely so a doomed request is refused before its body is read.
     *
     * <p>Only replacement is governed. Creating is unconditional, and {@code DELETE} stays optionally
     * conditional; {@code PATCH} is governed too, by {@link #requireConditionalChange}.
     *
     * <p>{@code If-None-Match: *} satisfies the rule as well, and <em>only</em> in that form. A
     * create-only {@code PUT} is a conditional request — it says "do this only if nothing is here" —
     * so refusing it with {@code 428} for want of an {@code If-Match} would demand a tag for a
     * resource the client is asserting does not exist. It gets the {@code 412} it has asked for
     * instead. A tag <em>list</em> deliberately does not qualify: {@code If-None-Match: "anything"}
     * names no version of this resource, so accepting it would turn one junk header into the
     * unconditional overwrite this rule exists to refuse (findings L28, and H23/M20 for why).
     */
    private static void requireConditionalReplace(IfMatch ifMatch, IfNoneMatch ifNoneMatch,
            LwsResource cur) {
        if (cur.etag() != null && !ifMatch.isPresent() && !ifNoneMatch.isStar()) {
            throw LwsException.preconditionRequired(
                    "If-Match is required to replace an existing resource: " + cur.iri());
        }
    }

    /**
     * {@code PATCH} names the version it changes, exactly as {@code PUT} does.
     *
     * <p>A patch is a read-modify-write against a version the client has already read — the shape
     * the mandatory-precondition rule exists for — and it was the one such method that accepted an
     * unconditional request (prior-review finding 14). Two clients could patch the same resource
     * from the same starting state and the second silently discarded the first's change, with no
     * error either could see; the {@code If-Match} compare-and-swap H23 added only helps a client
     * that chose to send one.
     *
     * <p>{@code DELETE} is deliberately left optional. It is not an update, it does not depend on
     * having read a version, and RFC 9110 asks for no precondition on it; requiring one would break
     * every ordinary cleanup without closing a lost update, because there is no "lost" state after a
     * delete.
     *
     * <p>This is a breaking change for a client that patches unconditionally: such a request now
     * gets {@code 428 Precondition Required}, naming the header to send.
     */
    private static void requireConditionalChange(IfMatch ifMatch, LwsResource cur) {
        if (cur.etag() != null && !ifMatch.isPresent()) {
            throw LwsException.preconditionRequired(
                    "If-Match is required to modify an existing resource: " + cur.iri());
        }
    }

    /**
     * The {@code If-None-Match} half of the compare-and-swap: the write proceeds only when no
     * current representation matches what the client named (RFC 9110 &sect;13.1.2).
     *
     * <p>Like {@link #requirePrecondition}, the message names nothing about the resource: a caller
     * can reach a {@code 412} without being able to read what it is conditioning on.
     */
    private static void requireNoneMatch(IfNoneMatch ifNoneMatch, LwsResource existing) {
        if (!ifNoneMatch.satisfiedBy(existing)) {
            throw LwsException.preconditionFailed("Precondition Failed");
        }
    }

    /**
     * The compare-and-swap at the heart of a conditional write: the tag the client conditioned on,
     * compared against the one just read from the store, <em>inside</em> the write transaction that
     * is about to make the change.
     *
     * <p>That placement is the whole point. The store admits a single writer, so a tag compared
     * under that writer's lock cannot go stale before the write it guards. The HTTP layer also
     * compares it earlier, so a doomed request is refused before its body is read, but that check
     * decides nothing: it ran in a transaction that had already closed, which let every writer
     * holding the same tag pass and commit in turn, each answering {@code 204} while discarding the
     * one before it (finding H23).
     *
     * <p>The message names nothing about the resource. A caller can reach a {@code 412} without
     * being able to read what it is conditioning on, so the tag it failed to match is not ours to
     * disclose.
     */
    private static void requirePrecondition(IfMatch ifMatch, LwsResource existing) {
        if (!ifMatch.satisfiedBy(existing)) {
            throw LwsException.preconditionFailed("Precondition Failed");
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
