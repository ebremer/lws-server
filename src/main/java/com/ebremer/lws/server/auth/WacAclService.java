package com.ebremer.lws.server.auth;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.vocabulary.RDF;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.AclMode;
import com.ebremer.lws.server.core.ActivityKind;
import com.ebremer.lws.server.core.Authorizer;
import com.ebremer.lws.server.core.Iris;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.RequestContext;
import com.ebremer.lws.server.core.ResourceEvent;
import com.ebremer.lws.server.core.ResourceEventListener;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.vocab.ACL;
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
 * <p>Each ACL is stored as a named graph addressed by the ACL resource IRI ({@code <resource>.acl},
 * or {@code <container>/.acl}). Access to an ACL resource is governed by {@code acl:Control} on its
 * target (so ACLs are not recursively access-controlled).
 *
 * @author Erich Bremer
 */
public final class WacAclService implements Authorizer, ResourceEventListener {

    private static final Logger log = LoggerFactory.getLogger(WacAclService.class);

    private static final long GROUP_TTL_MS = 5 * 60 * 1000L;

    private final RdfStore rdf;
    private final LwsConfiguration config;
    // Bounded, TTL-evicting cache of agentGroup membership (Caffeine handles expiry and eviction).
    private final Cache<String, Set<String>> groupCache = Caffeine.newBuilder()
            .expireAfterWrite(GROUP_TTL_MS, TimeUnit.MILLISECONDS).maximumSize(1_000).build();
    private final OutboundFetchPolicy fetchPolicy;

    public WacAclService(RdfStore rdf, LwsConfiguration config) {
        this.rdf = rdf;
        this.config = config;
        this.fetchPolicy = OutboundFetchPolicy.from(config);
    }

    // ----- Authorizer -----

    @Override
    public boolean allows(LwsPrincipal principal, String targetIri, AclMode mode) {
        Resolution resolution = resolve(targetIri);
        if (resolution == null) {
            return false; // no governing ACL found (default deny)
        }
        for (Statement st : resolution.model().listStatements(null, resolution.scopeProp(), resolution.scope()).toList()) {
            Resource auth = st.getSubject();
            if (grants(auth, mode) && originAllowed(auth) && matches(resolution.model(), auth, principal)) {
                return true;
            }
        }
        return false;
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
            String value = st.getObject().isResource() ? st.getObject().asResource().getURI()
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
        Model own = fetchAcl(aclIriFor(targetIri));
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
            Model m = fetchAcl(aclIriFor(containerIri));
            if (!m.isEmpty()) {
                return new Resolution(m, ACL.defaultAccess, m.createResource(containerIri));
            }
            parent = Iris.parentPath(parent);
        }
        return null;
    }

    private static boolean grants(Resource auth, AclMode mode) {
        return switch (mode) {
            case READ -> auth.hasProperty(ACL.mode, ACL.Read);
            case WRITE -> auth.hasProperty(ACL.mode, ACL.Write);
            case APPEND -> auth.hasProperty(ACL.mode, ACL.Append) || auth.hasProperty(ACL.mode, ACL.Write);
            case CONTROL -> auth.hasProperty(ACL.mode, ACL.Control);
        };
    }

    private boolean matches(Model model, Resource auth, LwsPrincipal principal) {
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
                if (st.getObject().isResource()
                        && isMember(st.getObject().asResource().getURI(), principal.webId())) {
                    return true;
                }
            }
        }
        return false;
    }

    /** True if {@code agentWebId} is a {@code vcard:hasMember} of the group document (cached). */
    private boolean isMember(String groupIri, String agentWebId) {
        return groupMembers(groupIri).contains(agentWebId);
    }

    private Set<String> groupMembers(String groupIri) {
        Set<String> cached = groupCache.getIfPresent(groupIri);
        if (cached != null) {
            return cached;
        }
        Model doc = loadGroupDocument(groupIri);
        Set<String> members = new HashSet<>();
        for (Statement st : doc.getResource(groupIri).listProperties(VCARD.hasMember).toList()) {
            if (st.getObject().isResource()) {
                members.add(st.getObject().asResource().getURI());
            }
        }
        Set<String> immutable = Set.copyOf(members); // cached value must not be mutated by callers
        groupCache.put(groupIri, immutable);
        return immutable;
    }

    private Model loadGroupDocument(String groupIri) {
        String docUri = groupIri.contains("#") ? groupIri.substring(0, groupIri.indexOf('#')) : groupIri;
        if (Iris.toPath(config.baseUri(), docUri) != null) {
            return rdf.read(conn -> ModelFactory.createDefaultModel().add(conn.fetch(docUri)));
        }
        if (!fetchPolicy.permits(docUri)) {
            log.debug("Refusing to load group document {} (blocked by outbound-fetch policy)", docUri);
            return ModelFactory.createDefaultModel();
        }
        try {
            return RDFDataMgr.loadModel(docUri); // external group document
        } catch (RuntimeException e) {
            log.debug("Could not load group document {}: {}", docUri, e.toString());
            return ModelFactory.createDefaultModel();
        }
    }

    // ----- ACL resource addressing & CRUD -----

    /** The ACL resource IRI for a target resource IRI. */
    public String aclIriFor(String targetIri) {
        String path = Iris.toPath(config.baseUri(), targetIri);
        if (path == null) {
            return targetIri + ".acl";
        }
        return config.baseUri() + path + ".acl";
    }

    public boolean isAclPath(String path) {
        return path.endsWith(".acl");
    }

    /** The path of the resource governed by an ACL path (strips the {@code .acl} suffix). */
    public String targetPathOf(String aclPath) {
        return aclPath.substring(0, aclPath.length() - ".acl".length());
    }

    public Model getAclModel(String targetIri) {
        return fetchAcl(aclIriFor(targetIri));
    }

    public boolean aclExistsFor(String targetIri) {
        return !getAclModel(targetIri).isEmpty();
    }

    public void putAclFor(String targetIri, Model acl) {
        rdf.writeDo(conn -> conn.put(aclIriFor(targetIri), acl));
    }

    public void deleteAclFor(String targetIri) {
        rdf.writeDo(conn -> conn.delete(aclIriFor(targetIri)));
    }

    private Model fetchAcl(String aclIri) {
        return rdf.read(conn -> ModelFactory.createDefaultModel().add(conn.fetch(aclIri)));
    }

    // ----- ResourceEventListener: drop a resource's ACL when the resource is deleted -----

    @Override
    public void onResourceEvent(ResourceEvent event) {
        if (event.kind() == ActivityKind.DELETE) {
            try {
                deleteAclFor(event.iri());
            } catch (RuntimeException e) {
                log.warn("Could not remove ACL for deleted resource {}: {}", event.iri(), e.toString());
            }
        }
    }

    // ----- Bootstrap -----

    /**
     * Ensure the storage root has an ACL so the system is usable and ACLs are manageable.
     * Configured owners get Read/Write/Control over everything (via {@code acl:default}); if no
     * owners are configured the root is opened to the public (development mode).
     */
    public void bootstrapRootAcl() {
        String rootIri = config.storageRootIri();
        if (aclExistsFor(rootIri)) {
            return;
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
            log.warn("WAC enabled with no owners configured: root ACL grants the PUBLIC full control "
                    + "(development mode). Set 'lws.owners' to lock down.");
        }
        putAclFor(rootIri, m);
    }
}
