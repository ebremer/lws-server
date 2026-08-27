package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Properties;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.AclMode;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.RequestContext;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.vocab.ACL;
import com.ebremer.lws.server.vocab.VCARD;
import com.ebremer.lws.server.vocab.FOAF;

/**
 * Unit tests for the Web Access Control engine: owner control, public vs authenticated access,
 * per-agent grants, container inheritance via {@code acl:default}, and nearest-ACL override.
 *
 * @author Erich Bremer
 */
class WacAclServiceTest {

    private static final String BASE = "http://localhost:8080";
    private static final String ROOT = BASE + "/";
    private static final String SHARED = BASE + "/shared/";
    private static final String MEMBERS = BASE + "/members/";

    private static final String ALICE = "https://alice.example/profile#me"; // storage owner
    private static final String BOB = "https://bob.example/profile#me";
    private static final String CAROL = "https://carol.example/profile#me";

    private WacAclService wac;
    private Tdb2RdfStore store;
    private LwsConfiguration config;
    private final LwsPrincipal alice = new LwsPrincipal(ALICE, "iss", null);
    private final LwsPrincipal bob = new LwsPrincipal(BOB, "iss", null);
    private final LwsPrincipal carol = new LwsPrincipal(CAROL, "iss", null);

    @BeforeEach
    void setUp() {
        store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.access-control", "wac");
        p.setProperty("lws.owners", ALICE);
        p.setProperty("lws.public-read", "true");
        config = LwsConfiguration.of(p);
        wac = new WacAclService(store, config);
        wac.bootstrapRootAcl();
    }

    @Test
    void ownerHasFullControlEverywhereByInheritance() {
        assertTrue(wac.allows(alice, ROOT, AclMode.READ));
        assertTrue(wac.allows(alice, ROOT, AclMode.WRITE));
        assertTrue(wac.allows(alice, ROOT, AclMode.CONTROL));
        // inherited down the tree
        assertTrue(wac.allows(alice, BASE + "/anything/deep/x", AclMode.WRITE));
        assertTrue(wac.allows(alice, BASE + "/anything/deep/x", AclMode.CONTROL));
    }

    @Test
    void publicReadButNotWriteAtRoot() {
        assertTrue(wac.allows(null, ROOT, AclMode.READ));
        assertFalse(wac.allows(null, ROOT, AclMode.WRITE));
        assertFalse(wac.allows(null, ROOT, AclMode.CONTROL));
    }

    @Test
    void nonOwnerGetsOnlyPublicAccessByDefault() {
        assertTrue(wac.allows(bob, ROOT, AclMode.READ));   // public read
        assertFalse(wac.allows(bob, ROOT, AclMode.WRITE)); // no write granted
    }

    @Test
    void perAgentGrantWithContainerInheritance() {
        // Owner grants Bob read+write over /shared/ and everything beneath it.
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(SHARED));
        a.addProperty(ACL.defaultAccess, acl.createResource(SHARED));
        a.addProperty(ACL.agent, acl.createResource(BOB));
        a.addProperty(ACL.mode, ACL.Read);
        a.addProperty(ACL.mode, ACL.Write);
        wac.putSystemAclFor(SHARED, acl);

        assertTrue(wac.allows(bob, SHARED, AclMode.WRITE));
        assertTrue(wac.allows(bob, SHARED, AclMode.APPEND));          // Write implies Append
        assertTrue(wac.allows(bob, SHARED + "doc", AclMode.WRITE));   // inherited
        assertTrue(wac.allows(bob, SHARED + "deep/nested/x", AclMode.WRITE)); // deep inheritance

        // Carol (another user) gets nothing here.
        assertFalse(wac.allows(carol, SHARED + "doc", AclMode.WRITE));
        assertFalse(wac.allows(carol, SHARED + "doc", AclMode.READ));

        // The nearest ACL (/shared/) overrides the root: it grants no public read,
        // so the public cannot read inside /shared/ even though root allows public read.
        assertFalse(wac.allows(null, SHARED + "doc", AclMode.READ));
        assertTrue(wac.allows(null, ROOT, AclMode.READ));

        // WAC has no "super-owner": because /shared/ has its own ACL that omits Alice, the root's
        // owner grant no longer applies within /shared/ (nearest ACL wins). Alice would need to
        // include herself in /shared/'s ACL to retain access to this subtree.
        assertFalse(wac.allows(alice, SHARED + "doc", AclMode.WRITE));
    }

    @Test
    void authenticatedAgentClass() {
        // Any authenticated agent may read /members/, but the public may not.
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(MEMBERS));
        a.addProperty(ACL.defaultAccess, acl.createResource(MEMBERS));
        a.addProperty(ACL.agentClass, ACL.AuthenticatedAgent);
        a.addProperty(ACL.mode, ACL.Read);
        wac.putSystemAclFor(MEMBERS, acl);

        assertTrue(wac.allows(bob, MEMBERS + "notice", AclMode.READ));
        assertTrue(wac.allows(carol, MEMBERS + "notice", AclMode.READ));
        assertFalse(wac.allows(null, MEMBERS + "notice", AclMode.READ)); // anonymous excluded
        assertFalse(wac.allows(bob, MEMBERS + "notice", AclMode.WRITE)); // read-only grant
    }

    @Test
    void publicAgentClassGrantsEveryone() {
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(BASE + "/public-note"));
        a.addProperty(ACL.agentClass, FOAF.Agent);
        a.addProperty(ACL.mode, ACL.Read);
        wac.putSystemAclFor(BASE + "/public-note", acl);

        assertTrue(wac.allows(null, BASE + "/public-note", AclMode.READ));
        assertTrue(wac.allows(carol, BASE + "/public-note", AclMode.READ));
    }

    @Test
    void originRestrictedAuthorization() {
        // Bob may write /app/ only from the trusted application origin.
        String appDir = BASE + "/app/";
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(appDir));
        a.addProperty(ACL.defaultAccess, acl.createResource(appDir));
        a.addProperty(ACL.agent, acl.createResource(BOB));
        a.addProperty(ACL.origin, acl.createResource("https://app.example"));
        a.addProperty(ACL.mode, ACL.Read);
        a.addProperty(ACL.mode, ACL.Write);
        wac.putSystemAclFor(appDir, acl);
        try {
            RequestContext.setOrigin("https://app.example");
            assertTrue(wac.allows(bob, appDir + "doc", AclMode.WRITE));   // matching Origin
            // A non-origin-restricted authorization (public read at the root) still applies.
            assertTrue(wac.allows(null, ROOT, AclMode.READ));

            RequestContext.setOrigin("https://evil.example");
            assertFalse(wac.allows(bob, appDir + "doc", AclMode.WRITE));  // wrong Origin

            RequestContext.clear();
            assertFalse(wac.allows(bob, appDir + "doc", AclMode.WRITE));  // no Origin header at all
        } finally {
            RequestContext.clear();
        }
    }

    @Test
    void agentGroupMembership() {
        String group = BASE + "/groups/team";
        // Store the group document locally: <group> vcard:hasMember <bob>.
        org.apache.jena.rdf.model.Model groupDoc = ModelFactory.createDefaultModel();
        groupDoc.createResource(group).addProperty(VCARD.hasMember, groupDoc.createResource(BOB));
        store.writeDo(conn -> conn.put(group, groupDoc));

        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(SHARED));
        a.addProperty(ACL.defaultAccess, acl.createResource(SHARED));
        a.addProperty(ACL.agentGroup, acl.createResource(group));
        a.addProperty(ACL.mode, ACL.Read);
        a.addProperty(ACL.mode, ACL.Write);
        wac.putSystemAclFor(SHARED, acl);

        assertTrue(wac.allows(bob, SHARED + "doc", AclMode.WRITE));    // member of the group
        assertFalse(wac.allows(carol, SHARED + "doc", AclMode.WRITE)); // not a member
        assertFalse(wac.allows(null, SHARED + "doc", AclMode.READ));   // anonymous is not a member
    }

    // ----- the development root ACL, and what happens when owners arrive -----

    /**
     * With no owners the bootstrap opens the storage to the public, and it used to write that once
     * and never revisit it — so an operator who tried WAC on the defaults and then set
     * {@code lws.owners} kept a root ACL granting everybody Read, Write and Control. The lockdown
     * they had just performed did nothing, and every access-grant issuer still "controlled" the
     * storage, which defeats the H22 re-check as well.
     */
    @Test
    void theDevelopmentRootAclIsRebuiltOnceOwnersAreConfigured() {
        // Its own store: the shared fixture has already bootstrapped an owner-derived root ACL.
        Tdb2RdfStore fresh = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        try {
            Properties open = new Properties();
            open.setProperty("lws.base-uri", BASE);
            open.setProperty("lws.access-control", "wac");
            open.setProperty("lws.dev.open", "true");
            WacAclService development = new WacAclService(fresh, LwsConfiguration.of(open));
            development.bootstrapRootAcl();
            assertTrue(development.allows(carol, ROOT, AclMode.CONTROL), "development mode opens the root");

            // The same store, now with an owner.
            WacAclService lockedDown = new WacAclService(fresh, config);
            lockedDown.bootstrapRootAcl();
            assertTrue(lockedDown.allows(alice, ROOT, AclMode.CONTROL), "the owner controls the storage");
            assertFalse(lockedDown.allows(carol, ROOT, AclMode.CONTROL), "and a stranger no longer does");
            assertFalse(lockedDown.allows(carol, ROOT, AclMode.WRITE));

            // Idempotent: a third pass changes nothing.
            Model after = lockedDown.getAclModel(ROOT);
            lockedDown.bootstrapRootAcl();
            assertTrue(after.isIsomorphicWith(lockedDown.getAclModel(ROOT)));
        } finally {
            fresh.close();
        }
    }

    /** An ACL the operator wrote is theirs. It is warned about, never replaced. */
    @Test
    void aRootAclTheOperatorWroteIsNeverRebuilt() {
        Model deliberate = ModelFactory.createDefaultModel();
        Resource a = deliberate.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, deliberate.createResource(ROOT));
        a.addProperty(ACL.defaultAccess, deliberate.createResource(ROOT));
        a.addProperty(ACL.agentClass, FOAF.Agent);
        a.addProperty(ACL.mode, ACL.Read);
        a.addProperty(ACL.mode, ACL.Control);
        wac.putSystemAclFor(ROOT, deliberate);

        wac.bootstrapRootAcl();

        assertTrue(deliberate.isIsomorphicWith(wac.getAclModel(ROOT)),
                "a hand-written root ACL carries no development marker and must survive");
    }

    // ----- C2: an ACL is not stored where a client can write it -----

    /**
     * The address a client uses and the graph the server reads are deliberately different strings.
     * They used to be the same, and that is finding C2: resource content is stored in a graph named
     * by the resource's own IRI, so creating a resource at {@code /shared/.acl} wrote the ACL.
     */
    @Test
    void aclsAreNotStoredAtTheAddressTheyAreAdvertisedAt() {
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(SHARED));
        a.addProperty(ACL.agent, acl.createResource(BOB));
        a.addProperty(ACL.mode, ACL.Read);
        wac.putSystemAclFor(SHARED, acl);

        assertEquals(BASE + "/shared/.acl", wac.aclIriFor(SHARED), "the advertised address is unchanged");
        assertTrue(graph(SHARED + ".acl").isEmpty(), "nothing is written where a client could reach it");
        assertFalse(graph(WacAclService.aclGraphName(SHARED)).isEmpty());
        // It governs its target from there — the move is invisible to every decision.
        assertTrue(wac.allows(bob, SHARED, AclMode.READ));
    }

    /**
     * The C2 payload itself, written straight into the graph {@code POST /shared/} with
     * {@code Slug: .acl} used to produce. It must change no decision at all.
     */
    @Test
    void aGraphAtTheAdvertisedAclAddressGovernsNothing() {
        Model pwn = ModelFactory.createDefaultModel();
        Resource a = pwn.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, pwn.createResource(SHARED));
        a.addProperty(ACL.defaultAccess, pwn.createResource(SHARED));
        a.addProperty(ACL.agent, pwn.createResource(CAROL));
        a.addProperty(ACL.mode, ACL.Read);
        a.addProperty(ACL.mode, ACL.Write);
        a.addProperty(ACL.mode, ACL.Control);
        store.writeDo(conn -> conn.put(SHARED + ".acl", pwn));

        assertFalse(wac.allows(carol, SHARED, AclMode.CONTROL));
        assertFalse(wac.allows(carol, SHARED, AclMode.WRITE));
        assertFalse(wac.allows(carol, SHARED + "doc", AclMode.WRITE));
        // ... and the root's own ACL is likewise untouchable from that namespace.
        store.writeDo(conn -> conn.put(ROOT + ".acl", pwn));
        assertFalse(wac.allows(carol, ROOT, AclMode.CONTROL));
        assertTrue(wac.allows(alice, ROOT, AclMode.CONTROL), "the owner keeps control");
    }

    private Model graph(String name) {
        return store.read(conn -> ModelFactory.createDefaultModel().add(conn.fetch(name)));
    }

    // ----- external group documents: what may be dereferenced, and when (H16) -----

    private static final String EXTERNAL_GROUP = "https://groups.example/team";

    /** A stubbed loader that counts fetches and notices any made while a transaction is open. */
    private static final class RecordingLoader implements DocumentLoader {

        private final RdfStore store;
        private final Model[] responses;
        private int calls;
        private boolean fetchedInsideTransaction;

        /** Answers with {@code responses[n]} on the n-th call, repeating the last one thereafter. */
        RecordingLoader(RdfStore store, Model... responses) {
            this.store = store;
            this.responses = responses;
        }

        @Override
        public String load(String url) {
            return null;
        }

        @Override
        public Model loadRdf(String url) {
            if (store.inUnitOfWork()) {
                fetchedInsideTransaction = true;
            }
            Model answer = responses[Math.min(calls, responses.length - 1)];
            calls++;
            return answer;
        }
    }

    private static Model groupDocumentWith(String member) {
        Model doc = ModelFactory.createDefaultModel();
        doc.createResource(EXTERNAL_GROUP).addProperty(VCARD.hasMember, doc.createResource(member));
        return doc;
    }

    /** Grants Read+Write over {@code SHARED} to the members of every {@code group} listed. */
    private void grantToGroups(WacAclService service, String... groups) {
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(SHARED));
        a.addProperty(ACL.defaultAccess, acl.createResource(SHARED));
        for (String group : groups) {
            a.addProperty(ACL.agentGroup, acl.createResource(group));
        }
        a.addProperty(ACL.mode, ACL.Read);
        a.addProperty(ACL.mode, ACL.Write);
        service.putSystemAclFor(SHARED, acl);
    }

    private WacAclService serviceWith(DocumentLoader loader, String... extraProperties) {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.access-control", "wac");
        p.setProperty("lws.owners", ALICE);
        p.setProperty("lws.public-read", "true");
        for (int i = 0; i < extraProperties.length; i += 2) {
            p.setProperty(extraProperties[i], extraProperties[i + 1]);
        }
        return new WacAclService(store, LwsConfiguration.of(p), loader);
    }

    /**
     * H16. The store admits one writer for the whole dataset, so an authorization decision made
     * inside a write transaction must not dereference anything: the group address comes out of the
     * requester's own ACL, and a host that never answers would stall every other write in the
     * storage. The fetch is refused there and done through {@code prepare} beforehand instead.
     */
    @Test
    void anExternalGroupDocumentIsNeverDereferencedInsideATransaction() {
        RecordingLoader loader = new RecordingLoader(store, groupDocumentWith(BOB));
        WacAclService service = serviceWith(loader);
        grantToGroups(service, EXTERNAL_GROUP);

        // Cold cache, inside a write transaction: the fetch is refused, so the group cannot match.
        boolean cold = store.write(conn -> service.allows(bob, SHARED + "doc", AclMode.WRITE));
        assertFalse(cold);
        assertEquals(0, loader.calls, "no outbound fetch may happen under the writer lock");

        // Warmed outside the transaction first, the same decision resolves from cache and allows.
        service.prepare(bob, SHARED + "doc", AclMode.WRITE);
        assertEquals(1, loader.calls);
        boolean warmed = store.write(conn -> service.allows(bob, SHARED + "doc", AclMode.WRITE));
        assertTrue(warmed);
        assertEquals(1, loader.calls, "the in-transaction decision must be a cache hit");
        assertFalse(loader.fetchedInsideTransaction);
    }

    /**
     * A document that could not be retrieved says nothing about the group's membership, so it must
     * not be remembered as one: caching a failed load as "this group has no members" denied every
     * member of a perfectly good group, for every principal, for the full positive TTL.
     */
    @Test
    void aFailedGroupFetchIsNotRememberedAsAnEmptyGroup() {
        // Unavailable on the first attempt, available on the second; retried at once because the
        // failure TTL is off.
        RecordingLoader loader = new RecordingLoader(store, null, groupDocumentWith(BOB));
        WacAclService service = serviceWith(loader, "lws.wac.group-failure-cache-seconds", "0");
        grantToGroups(service, EXTERNAL_GROUP);

        assertFalse(service.allows(bob, SHARED + "doc", AclMode.WRITE)); // could not be resolved
        assertTrue(service.allows(bob, SHARED + "doc", AclMode.WRITE));  // resolves on the retry
        assertEquals(2, loader.calls);
    }

    /** But an address that stays unreachable is not dereferenced once per request either. */
    @Test
    void anUnreachableGroupDocumentIsNotRefetchedOnEveryDecision() {
        RecordingLoader loader = new RecordingLoader(store, (Model) null);
        WacAclService service = serviceWith(loader); // default 30s failure TTL
        grantToGroups(service, EXTERNAL_GROUP);

        for (int i = 0; i < 5; i++) {
            assertFalse(service.allows(bob, SHARED + "doc", AclMode.WRITE));
        }
        assertEquals(1, loader.calls);
    }

    /**
     * {@code prepare} is advisory: it runs before the existence check its caller performs inside the
     * transaction, so anything it let escape would surface as a {@code 500} on a request that should
     * have been a {@code 404}. A blank node as {@code acl:agentGroup} is one way to make the
     * decision itself throw (recorded as N1-series finding N4 in {@code REVIEW.md}); the warm-up has
     * to absorb it and leave the real decision to fail in its proper place.
     */
    @Test
    void prepareIsAdvisoryAndNeverThrows() {
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(SHARED));
        a.addProperty(ACL.defaultAccess, acl.createResource(SHARED));
        a.addProperty(ACL.agentGroup, acl.createResource()); // a blank node, not an IRI
        a.addProperty(ACL.mode, ACL.Write);
        wac.putSystemAclFor(SHARED, acl);

        assertDoesNotThrow(() -> wac.prepare(bob, SHARED + "doc", AclMode.WRITE));
    }

    // ----- finding N4: a malformed ACL denies, it does not throw -----

    /**
     * Finding N4. {@code matches} tested {@code isResource()}, which is true for a blank node, and
     * then passed {@code asResource().getURI()} — {@code null} — into the group cache. Anyone with
     * {@code acl:Control} over their own resource could write such an ACL and turn every request
     * for it into a {@code 500}, for every principal, permanently.
     *
     * <p>{@code prepareIsAdvisoryAndNeverThrows} above uses the same ACL but only exercises the
     * warm-up, which swallows everything; this drives the decision itself, which does not.
     */
    @Test
    void aBlankNodeAgentGroupDeniesRatherThanThrowing() {
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(SHARED));
        a.addProperty(ACL.defaultAccess, acl.createResource(SHARED));
        a.addProperty(ACL.agentGroup, acl.createResource()); // a blank node, not an IRI
        a.addProperty(ACL.mode, ACL.Write);
        wac.putSystemAclFor(SHARED, acl);

        assertFalse(assertDoesNotThrow(() -> wac.allows(bob, SHARED + "doc", AclMode.WRITE)),
                "a blank-node acl:agentGroup names no group, so it matches nobody");
    }

    /**
     * The second site, which the review did not record. A blank node in the group <em>document</em>
     * yields a null member, and {@code Set.copyOf} rejects nulls outright — so one
     * {@code vcard:hasMember [ ]} threw out of the middle of the decision. Note this denies even the
     * member who genuinely is in the group, so it is a full denial as well as a {@code 500}; and a
     * local group document is an ordinary resource, so an agent with Write on it could do this to
     * every request governed by someone else's ACL.
     */
    @Test
    void aBlankNodeGroupMemberIsIgnoredRatherThanThrowing() {
        String group = BASE + "/groups/team";
        Model groupDoc = ModelFactory.createDefaultModel();
        Resource g = groupDoc.createResource(group);
        g.addProperty(VCARD.hasMember, groupDoc.createResource()); // a blank node member
        g.addProperty(VCARD.hasMember, groupDoc.createResource(BOB));
        store.writeDo(conn -> conn.put(group, groupDoc));

        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(SHARED));
        a.addProperty(ACL.defaultAccess, acl.createResource(SHARED));
        a.addProperty(ACL.agentGroup, acl.createResource(group));
        a.addProperty(ACL.mode, ACL.Read);
        a.addProperty(ACL.mode, ACL.Write);
        wac.putSystemAclFor(SHARED, acl);

        assertTrue(assertDoesNotThrow(() -> wac.allows(bob, SHARED + "doc", AclMode.WRITE)),
                "a malformed member must be skipped, not deny the members that are well-formed");
        assertFalse(wac.allows(carol, SHARED + "doc", AclMode.WRITE));
    }

    /**
     * A local {@code acl:agentGroup} whose document was never written. TDB2 answers an absent graph
     * with an empty model, so this denies; the fix that matters is that the read goes through the
     * same {@code fetchOrEmpty} the ACL lookup uses, because a remote Graph Store Protocol backend
     * answers {@code 404} and an unabsorbed {@code 404} here is a {@code 500} on every decision.
     */
    @Test
    void anAbsentLocalGroupDocumentDeniesRatherThanThrowing() {
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(SHARED));
        a.addProperty(ACL.defaultAccess, acl.createResource(SHARED));
        a.addProperty(ACL.agentGroup, acl.createResource(BASE + "/groups/never-written"));
        a.addProperty(ACL.mode, ACL.Write);
        wac.putSystemAclFor(SHARED, acl);

        assertFalse(assertDoesNotThrow(() -> wac.allows(bob, SHARED + "doc", AclMode.WRITE)));
    }

    /**
     * The number of group documents one decision dereferences is chosen by whoever wrote the ACL,
     * and a requester with {@code acl:Control} over their own resource writes that ACL. Cap it.
     */
    @Test
    void oneDecisionCannotDereferenceUnboundedlyManyGroupDocuments() {
        RecordingLoader loader = new RecordingLoader(store, (Model) null);
        WacAclService service = serviceWith(loader,
                "lws.wac.max-group-fetches-per-decision", "2",
                "lws.wac.group-failure-cache-seconds", "0");
        grantToGroups(service, "https://groups.example/a", "https://groups.example/b",
                "https://groups.example/c", "https://groups.example/d", "https://groups.example/e");

        assertFalse(service.allows(bob, SHARED + "doc", AclMode.WRITE));
        assertEquals(2, loader.calls);
    }
}
