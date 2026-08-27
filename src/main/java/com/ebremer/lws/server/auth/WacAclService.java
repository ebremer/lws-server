package com.ebremer.lws.server.auth;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.apache.jena.atlas.web.HttpException;
import org.apache.jena.rdfconnection.RDFConnection;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.vocabulary.RDF;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.AclMode;
import com.ebremer.lws.server.core.Etags;
import com.ebremer.lws.server.core.IfMatch;
import com.ebremer.lws.server.core.IfNoneMatch;
import com.ebremer.lws.server.core.Authorizer;
import com.ebremer.lws.server.core.Iris;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.RequestContext;
import com.ebremer.lws.server.core.ResourceCleanup;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.vocab.ACL;
import com.ebremer.lws.server.vocab.LWS;
import com.ebremer.lws.server.vocab.FOAF;
import com.ebremer.lws.server.vocab.VCARD;

/**
 * Web Access Control authorization engine and ACL resource manager.
 *
 * <p><b>Resolution.</b> The effective ACL for a resource is its own ACL ({@code acl:accessTo})
 * if one exists, otherwise the nearest ancestor container's ACL applied through
 * {@code acl:default} (container inheritance), walking up to the storage root.
 *
 * <p><b>Evaluation.</b> An authorization grants access if it scopes the target, grants the
 * required {@link AclMode} (with {@code acl:Write} implying {@code acl:Append}), and matches the
 * agent — by {@code acl:agent} (WebID), or {@code acl:agentClass} {@code foaf:Agent} (public) or
 * {@code acl:AuthenticatedAgent} (any signed-in agent).
 *
 * <p>Each ACL is stored as a named graph in the server-internal {@code urn:x-lws:acl:} namespace,
 * keyed by the target's IRI, while {@code <resource>.acl} remains the address it is advertised and
 * managed at. Keeping the two apart is what stops a client from writing its own governing ACL by
 * creating a resource at that address (finding C2). Access to an ACL resource is governed by
 * {@code acl:Control} on its target (so ACLs are not recursively access-controlled).
 *
 * @author Erich Bremer
 */
public final class WacAclService implements Authorizer, ResourceCleanup {

    private static final Logger log = LoggerFactory.getLogger(WacAclService.class);

    private final RdfStore rdf;
    private final LwsConfiguration config;
    // Bounded, TTL-evicting cache of agentGroup membership (Caffeine handles expiry and eviction).
    // Only documents that were actually resolved go in here: a resolved group with no members is a
    // fact about the group, but a group that could not be fetched is a fact about this attempt, and
    // recording the latter as "has no members" would deny every member of a perfectly good group,
    // for every principal, for the whole TTL.
    private final Cache<String, Set<String>> groupCache;
    // Group documents that could not be resolved, held for a much shorter time purely so an
    // unreachable (or hostile) address is not dereferenced once per request.
    private final Cache<String, Boolean> groupFailures;
    private final int maxGroupFetches;
    private final DocumentLoader loader;

    /** Uses the default policy-checked, size-capped HTTP loader for external group documents. */
    public WacAclService(RdfStore rdf, LwsConfiguration config) {
        this(rdf, config, new HttpDocumentLoader(OutboundFetchPolicy.from(config)));
    }

    public WacAclService(RdfStore rdf, LwsConfiguration config, DocumentLoader loader) {
        this.rdf = rdf;
        this.config = config;
        this.loader = loader;
        this.groupCache = Caffeine.newBuilder()
                .expireAfterWrite(config.wacGroupCacheSeconds(), TimeUnit.SECONDS)
                .maximumSize(1_000).build();
        this.groupFailures = Caffeine.newBuilder()
                .expireAfterWrite(config.wacGroupFailureCacheSeconds(), TimeUnit.SECONDS)
                .maximumSize(1_000).build();
        this.maxGroupFetches = config.wacMaxGroupFetchesPerDecision();
    }

    // ----- Authorizer -----

    @Override
    public boolean allows(LwsPrincipal principal, String targetIri, AclMode mode) {
        Resolution resolution = resolve(targetIri);
        if (resolution == null) {
            return false; // no governing ACL found (default deny)
        }
        FetchBudget budget = new FetchBudget(maxGroupFetches);
        for (Statement st : resolution.model().listStatements(null, resolution.scopeProp(), resolution.scope()).toList()) {
            Resource auth = st.getSubject();
            if (grants(auth, mode) && originAllowed(auth)
                    && matches(resolution.model(), auth, principal, budget)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Runs the decision for its side effect and throws the answer away: every group document the
     * real decision will consult ends up in {@link #groupCache}, so the real decision — made later,
     * inside the caller's transaction — needs no outbound request. Evaluating rather than
     * reimplementing the traversal is deliberate: it cannot drift from {@link #allows}, and it warms
     * exactly the documents that decision reaches, including the short-circuit at the first matching
     * authorization.
     *
     * <p>The pre-computed answer itself is discarded on purpose. Reusing it would substitute a
     * snapshot taken before the transaction for a decision that must see the state the write will
     * actually commit against — an ACL tightened, or a grant revoked, in the interval would be
     * invisible.
     */
    @Override
    public void prepare(LwsPrincipal principal, String targetIri, AclMode mode) {
        if (rdf.inUnitOfWork()) {
            // Warming from inside a transaction would be the very thing it exists to prevent.
            log.warn("Authorizer.prepare called for {} while a store transaction is open; skipping "
                    + "the warm-up (the decision will still be made, but may deny an agentGroup "
                    + "whose document is not cached)", targetIri);
            return;
        }
        try {
            allows(principal, targetIri, mode);
        } catch (RuntimeException e) {
            // Advisory by contract, so a warm-up that fails must not change what the caller sees.
            // Swallowing it here leaves the real decision to raise the same failure inside the
            // transaction, in its proper place — after the existence check, so a request for a
            // resource that does not exist still answers 404 rather than 500.
            log.debug("Could not resolve the authorization inputs for {}: {}", targetIri, e.toString());
        }
    }

    /**
     * How many group documents one authorization decision may still dereference.
     *
     * <p>{@link #allows} tries every authorization that scopes the target and every
     * {@code acl:agentGroup} on each, without short-circuiting on a non-match — so the number of
     * fetches is chosen by whoever wrote the ACL, and a requester with {@code acl:Control} over
     * their own resource writes that ACL. Passed down the call chain rather than held in a
     * thread-local so it cannot outlive the decision that created it.
     */
    private static final class FetchBudget {

        private int remaining;

        FetchBudget(int remaining) {
            this.remaining = remaining;
        }

        boolean take() {
            if (remaining <= 0) {
                return false;
            }
            remaining--;
            return true;
        }
    }

    /**
     * An authorization with one or more {@code acl:origin} values applies only to requests from a
     * matching web Origin (an "app", per the {@code Origin} header); one with none is unrestricted.
     */
    private static boolean originAllowed(Resource auth) {
        java.util.List<Statement> origins = auth.listProperties(ACL.origin).toList();
        if (origins.isEmpty()) {
            return true;
        }
        String requestOrigin = RequestContext.origin();
        if (requestOrigin == null) {
            return false; // origin-restricted, but the request carries no Origin
        }
        for (Statement st : origins) {
            // isURIResource, not isResource: behaviour is unchanged here (requestOrigin is non-null
            // by the check above, so a null value never matched), but no isResource()-then-getURI()
            // pair is left in this file for the next one to be copied from.
            String value = st.getObject().isURIResource() ? st.getObject().asResource().getURI()
                    : st.getObject().isLiteral() ? st.getObject().asLiteral().getString() : null;
            if (requestOrigin.equals(value)) {
                return true;
            }
        }
        return false;
    }

    private record Resolution(Model model, Property scopeProp, Resource scope) {
    }

    private Resolution resolve(String targetIri) {
        Model own = fetchAcl(aclGraphName(targetIri));
        if (!own.isEmpty()) {
            return new Resolution(own, ACL.accessTo, own.createResource(targetIri));
        }
        String path = Iris.toPath(config.baseUri(), targetIri);
        if (path == null) {
            return null;
        }
        String parent = Iris.parentPath(path);
        while (parent != null) {
            String containerIri = Iris.toIri(config.baseUri(), parent);
            Model m = fetchAcl(aclGraphName(containerIri));
            if (!m.isEmpty()) {
                return new Resolution(m, ACL.defaultAccess, m.createResource(containerIri));
            }
            parent = Iris.parentPath(parent);
        }
        return null;
    }

    /**
     * Map an {@link AclMode} onto the {@code acl:mode} values an authorization must carry.
     *
     * <p>{@link AclMode#DELETE} maps to {@code acl:Write}, because Web Access Control has no delete
     * permission: {@code acl:Write} is removal as well as modification, and there is no
     * {@code acl:Delete} in the vocabulary to map it to. The mode exists so that <em>access grants</em>
     * can honour the distinction ODRL draws between {@code modify} and {@code delete} (finding M8);
     * mapping it to anything else here — or leaving it unmatched — would refuse every delete in WAC
     * mode instead.
     */
    private static boolean grants(Resource auth, AclMode mode) {
        return switch (mode) {
            case READ -> auth.hasProperty(ACL.mode, ACL.Read);
            case WRITE, DELETE -> auth.hasProperty(ACL.mode, ACL.Write);
            case APPEND -> auth.hasProperty(ACL.mode, ACL.Append) || auth.hasProperty(ACL.mode, ACL.Write);
            case CONTROL -> auth.hasProperty(ACL.mode, ACL.Control);
        };
    }

    private boolean matches(Model model, Resource auth, LwsPrincipal principal, FetchBudget budget) {
        if (auth.hasProperty(ACL.agentClass, FOAF.Agent)) {
            return true; // public
        }
        if (principal != null && principal.webId() != null) {
            if (auth.hasProperty(ACL.agentClass, ACL.AuthenticatedAgent)) {
                return true;
            }
            if (auth.hasProperty(ACL.agent, model.createResource(principal.webId()))) {
                return true;
            }
            for (Statement st : auth.listProperties(ACL.agentGroup).toList()) {
                // isURIResource, not isResource: a blank node is a resource and its getURI() is
                // null, and that null reached the group cache and made every decision for this
                // resource a 500 (finding N4). A blank node is not an address, so it names no
                // group and matches nothing. Logged at debug rather than warn because the ACL is
                // written by whoever holds acl:Control over the target, so a per-request warning
                // would itself be a log-flooding primitive.
                if (!st.getObject().isURIResource()) {
                    log.debug("Ignoring a non-IRI acl:agentGroup on authorization {}", auth);
                    continue;
                }
                if (isMember(st.getObject().asResource().getURI(), principal.webId(), budget)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** True if {@code agentWebId} is a {@code vcard:hasMember} of the group document (cached). */
    private boolean isMember(String groupIri, String agentWebId, FetchBudget budget) {
        return groupMembers(groupIri, budget).contains(agentWebId);
    }

    /**
     * The members of {@code groupIri}, or an empty set if the group document cannot be resolved
     * right now. An unresolved group simply fails to match this one authorization; every other
     * authorization in the ACL still gets its chance, so this can only ever narrow a decision.
     */
    private Set<String> groupMembers(String groupIri, FetchBudget budget) {
        Set<String> cached = groupCache.getIfPresent(groupIri);
        if (cached != null) {
            return cached;
        }
        String docUri = groupIri.contains("#") ? groupIri.substring(0, groupIri.indexOf('#')) : groupIri;
        Model doc;
        if (Iris.toPath(config.baseUri(), docUri) != null) {
            // Held in this storage: a local read, no egress, and Jena folds it into an already-open
            // transaction rather than starting one, so it is safe wherever the decision is made.
            //
            // fetchOrEmpty, not a bare conn.fetch: TDB2 answers an absent graph with an empty model
            // but a remote Graph Store Protocol service answers 404, and an unabsorbed 404 here
            // turns every decision naming a local group with no document into a 500.
            doc = rdf.read(conn -> fetchOrEmpty(conn, docUri));
        } else {
            doc = fetchGroupDocument(docUri, budget);
            if (doc == null) {
                return Set.of();
            }
        }
        Set<String> members = new HashSet<>();
        for (Statement st : doc.getResource(groupIri).listProperties(VCARD.hasMember).toList()) {
            // isURIResource for the same reason as the acl:agentGroup test above, and here it is
            // not only a null in the set: Set.copyOf below rejects nulls outright, so a single
            // `vcard:hasMember [ ]` threw NullPointerException out of the middle of the decision.
            // A local group document is an ordinary resource a client can PUT, so an agent with
            // Write on it could 500 every request governed by someone else's ACL that names it.
            if (st.getObject().isURIResource()) {
                members.add(st.getObject().asResource().getURI());
            }
        }
        Set<String> immutable = Set.copyOf(members); // cached value must not be mutated by callers
        groupCache.put(groupIri, immutable);
        return immutable;
    }

    /**
     * Dereference an external group document, or return {@code null} if it cannot be had.
     *
     * <p>Three refusals live here, and only the last of them is remembered. A refusal because a
     * transaction is open, or because the decision has spent its fetch budget, is a fact about
     * <em>this caller</em>; recording it against the group would deny that group to every unrelated
     * request for as long as the entry lived. A document the remote host would not serve is a fact
     * about the document, and is held briefly so it is not re-fetched once per request.
     */
    private Model fetchGroupDocument(String docUri, FetchBudget budget) {
        if (groupFailures.getIfPresent(docUri) != null) {
            return null;
        }
        if (rdf.inUnitOfWork()) {
            // H16. TDB2 admits one writer for the whole dataset, so a fetch from here would stall
            // every other write in the storage for as long as the remote host chose to take - and
            // the address comes from the requester's own ACL. Callers warm this cache through
            // Authorizer.prepare before opening their transaction, so reaching this point means the
            // governing ACL changed in between, or the budget was already spent when it was warmed.
            // Refuse, and let the decision fail closed.
            log.warn("Refusing to dereference group document {} while a store transaction is open; "
                    + "this authorization will not match. See Authorizer.prepare.", docUri);
            return null;
        }
        if (!budget.take()) {
            log.warn("Refusing to dereference group document {}: this decision has already fetched "
                    + "{} group documents (lws.wac.max-group-fetches-per-decision)",
                    docUri, maxGroupFetches);
            return null;
        }
        // Fetched through the shared loader, which applies the outbound-fetch policy to every
        // redirect hop and bounds both the response size and the time spent. A bare
        // RDFDataMgr.loadModel here would have neither.
        Model document = loader.loadRdf(docUri);
        if (document == null) {
            log.debug("Could not load group document {}", docUri);
            groupFailures.put(docUri, Boolean.TRUE);
            return null;
        }
        return document;
    }

    // ----- ACL resource addressing & CRUD -----

    /**
     * The prefix of the internal named graph holding a resource's ACL, joined to the target's own
     * IRI. It follows the {@code urn:x-lws:admin} / {@code :linkset} / {@code :access} convention
     * already used for the server's other internal graphs, so everything under {@code urn:x-lws:}
     * remains "server-owned, not addressable by a client".
     */
    public static final String ACL_GRAPH_PREFIX = "urn:x-lws:acl:";

    /**
     * The named graph an ACL is stored in — deliberately <em>not</em> {@link #aclIriFor}.
     *
     * <p>The two used to be the same string, and that was finding C2: resource content is stored in
     * a graph named by the resource's own IRI, so creating a resource at {@code /c/.acl} wrote the
     * graph governing access to {@code /c/}. An agent holding only {@code acl:Append} on a container
     * could POST itself {@code acl:Control} over that container and its whole subtree, or replace
     * the storage root's ACL outright. Resource IRIs are always built from the {@code http(s)} base,
     * so no request can name a graph in this namespace.
     */
    public static String aclGraphName(String targetIri) {
        return ACL_GRAPH_PREFIX + targetIri;
    }

    /**
     * The ACL resource IRI advertised for a target resource — the address a client GETs, PUTs and
     * sees in a {@code Link: rel="acl"} header. Purely an address: see {@link #aclGraphName} for
     * where the graph actually lives.
     */
    public String aclIriFor(String targetIri) {
        String path = Iris.toPath(config.baseUri(), targetIri);
        if (path == null) {
            return targetIri + Iris.ACL_SUFFIX;
        }
        return config.baseUri() + path + Iris.ACL_SUFFIX;
    }

    /** The path of the resource governed by an ACL path (strips the {@code .acl} suffix). */
    public String targetPathOf(String aclPath) {
        return aclPath.substring(0, aclPath.length() - Iris.ACL_SUFFIX.length());
    }

    public Model getAclModel(String targetIri) {
        return fetchAcl(aclGraphName(targetIri));
    }

    /** An ACL and the entity-tag that names the version this is. */
    public record AclSnapshot(Model model, String etag) {
    }

    /**
     * A target's ACL and its entity-tag, read as one state.
     *
     * <p>Read separately they are two snapshots: a write landing between them yields a body from one
     * version and a tag from the next, and a client that then conditions a write on that tag has its
     * precondition satisfied by a version it never saw — the lost update the tag exists to prevent,
     * reintroduced by the two reads that hand it out. {@code ResourceService.read} takes metadata and
     * content in one transaction for the same reason, and {@code LinksetService.get} documents it.
     */
    public AclSnapshot readAcl(String targetIri) {
        return rdf.read(conn -> new AclSnapshot(fetchOrEmpty(conn, aclGraphName(targetIri)),
                readAclEtag(conn, targetIri)));
    }

    public boolean aclExistsFor(String targetIri) {
        return !getAclModel(targetIri).isEmpty();
    }

    /**
     * Write a target's ACL on behalf of a principal, refusing anyone without {@code acl:Control}
     * on that target.
     *
     * <p>The check lives here, at the write, rather than only at each caller. It used to live only
     * at the callers, and one of them — the console's {@code removeAcl} — did not have it: its only
     * gate was {@code aclBox.setVisible(canControl)}, a boolean captured once in the page
     * constructor and frozen into the serialized page, so a user whose Control had since been
     * revoked could still delete the ACL from a page they already had open (finding M11). Whether a
     * control is <em>shown</em> and whether it may <em>run</em> are different questions.
     */
    public void putAclFor(LwsPrincipal principal, String targetIri, Model acl) {
        putAclFor(principal, targetIri, acl, IfMatch.NONE, IfNoneMatch.NONE);
    }

    /**
     * As {@link #putAclFor(LwsPrincipal, String, Model)}, honouring the client's conditional-write
     * preconditions as a compare-and-swap inside the write transaction (prior-review finding 13).
     *
     * <p>An ACL is the one resource in this storage where a lost update is a <em>grant</em> of
     * access nobody chose: two controllers each read the ACL, each add an agent, each write back,
     * and the second silently discards the first — leaving an ACL that names one of the two agents
     * and looks, to both of them, as though it names both. Every other resource here has had a
     * mandatory precondition on replacement since M20; the ACL surface never did.
     */
    public void putAclFor(LwsPrincipal principal, String targetIri, Model acl, IfMatch ifMatch,
            IfNoneMatch ifNoneMatch) {
        requireControl(principal, targetIri);
        rdf.writeDo(conn -> {
            String current = readAclEtag(conn, targetIri);
            requireAclPrecondition(ifMatch, ifNoneMatch, current, targetIri);
            storeAcl(conn, targetIri, acl);
        });
    }

    /** Delete a target's ACL on behalf of a principal. See {@link #putAclFor}. */
    public void deleteAclFor(LwsPrincipal principal, String targetIri) {
        deleteAclFor(principal, targetIri, IfMatch.NONE);
    }

    /** As {@link #deleteAclFor(LwsPrincipal, String)}, honouring an {@code If-Match} if one is sent. */
    public void deleteAclFor(LwsPrincipal principal, String targetIri, IfMatch ifMatch) {
        requireControl(principal, targetIri);
        rdf.writeDo(conn -> {
            // namesState, not matches: a GET hands out the tag qualified by the serialization it
            // produced, and a client conditions its write on the tag it was given (finding M21).
            if (!ifMatch.namesState(readAclEtag(conn, targetIri))) {
                throw LwsException.preconditionFailed("Precondition Failed");
            }
            deleteGraphIfAbsentIsFine(conn, aclGraphName(targetIri));
            deleteAclEtag(conn, targetIri);
        });
    }

    /**
     * The rule an ACL write has to satisfy, mirroring the one every other resource has:
     * replacing something that exists must name the version it replaces.
     *
     * <p>An ACL written before this existed carries no tag, and then no precondition is demanded —
     * the same {@code etag() != null} guard {@code ResourceService.requireConditionalReplace} uses,
     * for the same reason: a client cannot be asked for a version identifier the server never gave
     * it. The first write through this path mints one, so a storage heals as its ACLs are edited.
     */
    private static void requireAclPrecondition(IfMatch ifMatch, IfNoneMatch ifNoneMatch, String current,
            String targetIri) {
        if (current != null && !ifMatch.isPresent() && !ifNoneMatch.isStar()) {
            throw LwsException.preconditionRequired(
                    "If-Match is required to replace an existing ACL: " + targetIri);
        }
        // namesState: an ACL read hands out a tag qualified by the serialization it produced, and
        // the client conditions its write on the tag it was given (finding M21).
        if (!ifMatch.namesState(current) || (ifNoneMatch.isStar() && current != null)) {
            throw LwsException.preconditionFailed("Precondition Failed");
        }
    }

    // ----- the ACL's entity-tag -----

    /**
     * The graph holding one entity-tag per ACL, beside the ACLs themselves in the server-owned
     * {@code urn:x-lws:} namespace.
     *
     * <p>Stored rather than derived. The obvious alternative — hashing the ACL model — does not work:
     * {@code Etags.forModel} sorts N-Triples lines, which makes it order-independent but not
     * blank-node-independent, and every authorization in an ACL <em>is</em> a blank node (see
     * {@link #bootstrapRootAcl}). The tag would have changed on every read, exactly as the storage
     * description's did (finding M22), and a validator that changes on every read cannot support a
     * conditional write at all.
     */
    static final String ACL_META_GRAPH = "urn:x-lws:acl-meta";
    private static final String ACL_ETAG = "urn:x-lws:aclEtag";

    /** The entity-tag of a target's ACL, or {@code null} if it has none (or no ACL). */
    public String aclEtag(String targetIri) {
        return rdf.read(conn -> readAclEtag(conn, targetIri));
    }

    private static String readAclEtag(RDFConnection conn, String targetIri) {
        org.apache.jena.query.ParameterizedSparqlString q =
                new org.apache.jena.query.ParameterizedSparqlString();
        q.setCommandText("SELECT ?e WHERE { GRAPH ?g { ?s ?p ?e } } LIMIT 1");
        q.setIri("g", ACL_META_GRAPH);
        q.setIri("s", aclGraphName(targetIri));
        q.setIri("p", ACL_ETAG);
        String[] holder = new String[1];
        conn.querySelect(q.asQuery(), row -> holder[0] = row.getLiteral("e").getString());
        return holder[0];
    }

    /**
     * Mint and store a fresh tag for a target's ACL.
     *
     * <p>Random rather than derived from a clock: two writes within the same millisecond would
     * otherwise share a tag, and the whole point of the value is that it changes whenever the ACL
     * does.
     */
    private static void writeAclEtag(RDFConnection conn, String targetIri) {
        deleteAclEtag(conn, targetIri);
        org.apache.jena.query.ParameterizedSparqlString u =
                new org.apache.jena.query.ParameterizedSparqlString();
        u.setCommandText("INSERT DATA { GRAPH ?g { ?s ?p ?e } }");
        u.setIri("g", ACL_META_GRAPH);
        u.setIri("s", aclGraphName(targetIri));
        u.setIri("p", ACL_ETAG);
        u.setLiteral("e", Etags.sha16(targetIri + "|" + java.util.UUID.randomUUID()));
        conn.update(u.asUpdate());
    }

    private static void deleteAclEtag(RDFConnection conn, String targetIri) {
        org.apache.jena.query.ParameterizedSparqlString u =
                new org.apache.jena.query.ParameterizedSparqlString();
        u.setCommandText("DELETE WHERE { GRAPH ?g { ?s ?p ?e } }");
        u.setIri("g", ACL_META_GRAPH);
        u.setIri("s", aclGraphName(targetIri));
        u.setIri("p", ACL_ETAG);
        conn.update(u.asUpdate());
    }

    private void requireControl(LwsPrincipal principal, String targetIri) {
        if (!allows(principal, targetIri, AclMode.CONTROL)) {
            if (LwsPrincipal.isAnonymous(principal)) {
                throw LwsException.unauthorized("Authentication required (CONTROL) for " + targetIri);
            }
            throw LwsException.forbidden("Not authorized (CONTROL) for " + targetIri);
        }
    }

    /**
     * Write an ACL with <strong>no</strong> Control check, for writes the server itself owns:
     * bootstrapping the root ACL, the legacy-ACL migration, and test fixtures. There is no requester
     * to authorize on these paths. Deliberately named so that a caller reaching for it, and anyone
     * reading the call site later, can see which one it is.
     */
    public void putSystemAclFor(String targetIri, Model acl) {
        rdf.writeDo(conn -> storeAcl(conn, targetIri, acl));
    }

    /**
     * Store an ACL and the tag naming this version of it — or, for an empty one, erase both.
     *
     * <p>An empty ACL graph *is* an absent ACL: {@link #resolve} treats it as absent and falls
     * through to container inheritance. Minting a tag for one therefore produced a resource that
     * {@code GET} answers {@code 404} for — so the tag is never disclosed — while {@code PUT} sees a
     * stored tag and demands an {@code If-Match} naming it. The result was an ACL address that could
     * not be read, could not be replaced, and could only be recovered by deleting it. Both writers
     * go through here so neither can acquire that state.
     */
    private static void storeAcl(RDFConnection conn, String targetIri, Model acl) {
        if (acl.isEmpty()) {
            deleteGraphIfAbsentIsFine(conn, aclGraphName(targetIri));
            deleteAclEtag(conn, targetIri);
            return;
        }
        conn.put(aclGraphName(targetIri), acl);
        writeAclEtag(conn, targetIri);
    }

    /**
     * Erase a target's ACL tag with no Control check, for the server's own ACL surgery. See
     * {@link #putSystemAclFor}; used by the legacy-ACL migration, which moves graphs directly.
     */
    public static void deleteSystemAclEtag(RDFConnection conn, String targetIri) {
        deleteAclEtag(conn, targetIri);
    }

    /** Mint a tag for a target's ACL with no Control check, on a caller-supplied connection. */
    public static void writeSystemAclEtag(RDFConnection conn, String targetIri) {
        writeAclEtag(conn, targetIri);
    }

    /** Delete an ACL with no Control check. See {@link #putSystemAclFor}. */
    public void deleteSystemAclFor(String targetIri) {
        rdf.writeDo(conn -> {
            deleteGraphIfAbsentIsFine(conn, aclGraphName(targetIri));
            deleteAclEtag(conn, targetIri);
        });
    }

    /**
     * Delete a named graph, treating "no such graph" as success.
     *
     * <p>The same backend disagreement {@link #fetchOrEmpty} absorbs on the read side: TDB2 makes
     * deleting a graph that is not there a no-op, while a remote Graph Store Protocol service
     * answers {@code 404}. Most resources have no ACL of their own, so now that this runs inside
     * the delete transaction (see {@link #onDelete}) an unabsorbed {@code 404} would abort every
     * delete of an ACL-less resource against that backend.
     */
    private static void deleteGraphIfAbsentIsFine(RDFConnection conn, String graphName) {
        try {
            conn.delete(graphName);
        } catch (HttpException e) {
            if (e.getStatusCode() != 404) {
                throw e;
            }
        }
    }

    private Model fetchAcl(String aclIri) {
        return rdf.read(conn -> fetchOrEmpty(conn, aclIri));
    }

    /**
     * Read a named graph as a detached copy, treating "no such graph" as empty.
     *
     * <p>The two backends disagree about that case: TDB2 hands back an empty model, while a remote
     * Graph Store Protocol service answers {@code 404}. Almost every authorization decision asks
     * about a graph that does not exist — a resource with no ACL of its own — so left unabsorbed
     * that difference would turn ordinary inheritance into a {@code 500} on the remote backend.
     */
    static Model fetchOrEmpty(RDFConnection conn, String graphName) {
        try {
            return ModelFactory.createDefaultModel().add(conn.fetch(graphName));
        } catch (HttpException e) {
            if (e.getStatusCode() == 404) {
                return ModelFactory.createDefaultModel();
            }
            throw e;
        }
    }

    // ----- ResourceCleanup: drop a resource's ACL in the transaction that deletes the resource -----

    /**
     * Erase a deleted resource's own ACL, in the delete's own unit of work.
     *
     * <p>It used to be a post-commit event listener that opened a transaction of its own and logged
     * whatever went wrong. A cleanup that failed therefore left the ACL behind, and a resource later
     * created at the same path inherited it: {@link #resolve} finds an own-ACL before it consults
     * container inheritance, so whoever the old ACL named silently kept access to a resource they
     * had never been granted (finding H24). It now commits or rolls back with the delete itself.
     */
    @Override
    public void onDelete(RDFConnection conn, String iri) {
        deleteGraphIfAbsentIsFine(conn, aclGraphName(iri));
        // The tag goes with the graph it describes, in the same unit of work. Left behind, it would
        // be the version identifier of an ACL that no longer exists, and a resource re-created at
        // this path would be handed it — the H24 resurrection, one indirection over.
        deleteAclEtag(conn, iri);
    }

    // ----- Bootstrap -----

    /**
     * Ensure the storage root has an ACL so the system is usable and ACLs are manageable.
     * Configured owners get Read/Write/Control over everything (via {@code acl:default}); if no
     * owners are configured the root is opened to the public (development mode).
     *
     * <p>The development ACL is marked as such, and is <em>replaced</em> the first time the server
     * starts with owners configured. Without that it was written once and never revisited, so an
     * operator who tried WAC on the defaults and then set {@code lws.owners} kept a root ACL
     * granting the public Read+Write+Control — the lockdown they had just performed did nothing.
     * (It also defeated the grant issuer re-check, since under that ACL every issuer still controls
     * the storage.) An ACL the server did not write carries no marker and is never touched: a
     * deliberate operator edit is theirs, and silently destroying it would be worse than the
     * warning it earns instead.
     */
    public void bootstrapRootAcl() {
        String rootIri = config.storageRootIri();
        Model existing = getAclModel(rootIri);
        if (!existing.isEmpty()) {
            boolean development = existing.getResource(rootIri).hasProperty(LWS.developmentBootstrap);
            if (!development || config.ownerWebIds().isEmpty()) {
                warnIfRootAclOpensControlToEveryone(existing, rootIri);
                return;
            }
            log.warn("Replacing the development root ACL (which granted the PUBLIC full control) with "
                    + "one built from lws.owners: {} owner(s)", config.ownerWebIds().size());
        }
        Model m = ModelFactory.createDefaultModel();
        m.setNsPrefix(ACL.PREFIX, ACL.NS);
        m.setNsPrefix(FOAF.PREFIX, FOAF.NS);
        Resource root = m.createResource(rootIri);

        if (!config.ownerWebIds().isEmpty()) {
            for (String owner : config.ownerWebIds()) {
                Resource a = m.createResource();
                a.addProperty(RDF.type, ACL.Authorization);
                a.addProperty(ACL.accessTo, root);
                a.addProperty(ACL.defaultAccess, root);
                a.addProperty(ACL.agent, m.createResource(owner));
                a.addProperty(ACL.mode, ACL.Read);
                a.addProperty(ACL.mode, ACL.Write);
                a.addProperty(ACL.mode, ACL.Control);
            }
            if (config.publicReadDefault()) {
                Resource pub = m.createResource();
                pub.addProperty(RDF.type, ACL.Authorization);
                pub.addProperty(ACL.accessTo, root);
                pub.addProperty(ACL.defaultAccess, root);
                pub.addProperty(ACL.agentClass, FOAF.Agent);
                pub.addProperty(ACL.mode, ACL.Read);
            }
            log.info("Bootstrapped root ACL: {} owner(s){}", config.ownerWebIds().size(),
                    config.publicReadDefault() ? " + public read" : "");
        } else {
            Resource pub = m.createResource();
            pub.addProperty(RDF.type, ACL.Authorization);
            pub.addProperty(ACL.accessTo, root);
            pub.addProperty(ACL.defaultAccess, root);
            pub.addProperty(ACL.agentClass, FOAF.Agent);
            pub.addProperty(ACL.mode, ACL.Read);
            pub.addProperty(ACL.mode, ACL.Write);
            pub.addProperty(ACL.mode, ACL.Control);
            // The marker is what lets a later startup tell this placeholder apart from an ACL an
            // operator wrote, so that only this one is ever replaced.
            root.addLiteral(LWS.developmentBootstrap, true);
            log.warn("WAC enabled with no owners configured: root ACL grants the PUBLIC full control "
                    + "(development mode). Set 'lws.owners' to lock down; the ACL is then rebuilt.");
        }
        putSystemAclFor(rootIri, m);
    }

    /**
     * Warn about a root ACL that hands {@code acl:Control} to everyone. Such an ACL makes every
     * agent a storage controller, which is the authority grant issuance and ACL editing borrow
     * from — so it is worth a line at every startup even though it is the operator's to change.
     */
    private void warnIfRootAclOpensControlToEveryone(Model acl, String rootIri) {
        Resource root = acl.getResource(rootIri);
        for (Statement st : acl.listStatements(null, ACL.accessTo, root).toList()) {
            Resource auth = st.getSubject();
            boolean everyone = auth.hasProperty(ACL.agentClass, FOAF.Agent)
                    || auth.hasProperty(ACL.agentClass, ACL.AuthenticatedAgent);
            if (everyone && auth.hasProperty(ACL.mode, ACL.Control)) {
                log.warn("The root ACL grants acl:Control to {}: every agent is a storage controller, "
                        + "and may issue access grants and edit any ACL. This server did not write "
                        + "that authorization and will not change it.",
                        auth.hasProperty(ACL.agentClass, FOAF.Agent) ? "foaf:Agent" : "acl:AuthenticatedAgent");
                return;
            }
        }
    }
}
