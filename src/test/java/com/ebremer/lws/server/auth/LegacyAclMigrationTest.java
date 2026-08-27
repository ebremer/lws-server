package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.time.Instant;
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
import com.ebremer.lws.server.core.LwsResource;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.core.ResourceType;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.vocab.ACL;

/**
 * A store written by an earlier build holds its ACLs at {@code <resource>.acl}, an ordinary
 * resource IRI. Two very different things can live at those names — an ACL this server wrote, and
 * a resource a client created there through finding C2 — and the migration has to carry the first
 * forward without ever promoting the second.
 *
 * @author Erich Bremer
 */
class LegacyAclMigrationTest {

    private static final String BASE = "http://localhost:8080";
    private static final String ALICE = "https://alice.example/profile#me";
    private static final String MALLORY = "https://mallory.example/profile#me";

    private LwsConfiguration config;
    private Tdb2RdfStore store;
    private ResourceRegistry registry;
    private WacAclService wac;

    private final LwsPrincipal alice = new LwsPrincipal(ALICE, "iss", null);
    private final LwsPrincipal mallory = new LwsPrincipal(MALLORY, "iss", null);

    @BeforeEach
    void setUp() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.access-control", "wac");
        p.setProperty("lws.owners", ALICE);
        p.setProperty("lws.public-read", "false");
        config = LwsConfiguration.of(p);
        store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        registry = new ResourceRegistry();
        wac = new WacAclService(store, config);
        register(config.storageRootIri()); // as ensureStorageRoot does, before the migration runs
    }

    @Test
    void aLegacyAclWrittenByAnEarlierBuildIsCarriedForward() {
        register(BASE + "/notes");
        writeGraph(BASE + "/notes.acl", grant(BASE + "/notes", ALICE, ACL.Read, ACL.Write));

        LegacyAclMigration.migrate(store, config, registry);

        assertTrue(graph(BASE + "/notes.acl").isEmpty(), "the client-reachable graph must be gone");
        assertFalse(wac.getAclModel(BASE + "/notes").isEmpty(), "the ACL must still govern its target");
        assertTrue(wac.allows(alice, BASE + "/notes", AclMode.WRITE));
    }

    /**
     * The C2 payload: a resource created at {@code /c/.acl} carries both a graph and a registry
     * entry, and that entry is the discriminator — {@code putAclFor} is the only writer in the
     * server that creates a graph without one.
     */
    @Test
    void aGraphPlantedThroughTheResourceApiIsNeverPromoted() {
        register(BASE + "/c/");
        register(BASE + "/c/.acl"); // what ResourceService.create writes alongside the graph
        writeGraph(BASE + "/c/.acl", grant(BASE + "/c/", MALLORY, ACL.Read, ACL.Write, ACL.Control));

        LegacyAclMigration.migrate(store, config, registry);

        assertTrue(wac.getAclModel(BASE + "/c/").isEmpty(), "a planted graph must not become an ACL");
        assertFalse(wac.allows(mallory, BASE + "/c/", AclMode.CONTROL));
        assertFalse(graph(BASE + "/c/.acl").isEmpty(), "quarantined, not deleted");
    }

    /**
     * The recovery property. If the storage root's ACL was replaced through the old address, the
     * planted graph is quarantined, the root is left with no ACL, and bootstrapping immediately
     * afterwards rebuilds it from {@code lws.owners} — so upgrading undoes the takeover.
     */
    @Test
    void anExploitedRootAclIsRebuiltFromTheConfiguredOwnersOnUpgrade() {
        register(BASE + "/.acl");
        writeGraph(BASE + "/.acl", grant(config.storageRootIri(), MALLORY, ACL.Read, ACL.Write, ACL.Control));

        LegacyAclMigration.migrate(store, config, registry);
        wac.bootstrapRootAcl();

        assertTrue(wac.allows(alice, config.storageRootIri(), AclMode.CONTROL), "the owner is back in control");
        assertFalse(wac.allows(mallory, config.storageRootIri(), AclMode.CONTROL));
        assertFalse(wac.allows(mallory, config.storageRootIri(), AclMode.WRITE));
    }

    /**
     * An ACL for a resource that does not exist cannot have been made through HTTP — an ACL
     * {@code PUT} requires its target — so it is debris, and left alone it would govern whatever is
     * created at that path next.
     */
    @Test
    void anAclWhoseTargetNoLongerExistsIsRemoved() {
        wac.putSystemAclFor(BASE + "/deleted", grant(BASE + "/deleted", MALLORY, ACL.Read, ACL.Write));
        assertFalse(wac.getAclModel(BASE + "/deleted").isEmpty());

        LegacyAclMigration.migrate(store, config, registry);

        assertTrue(wac.getAclModel(BASE + "/deleted").isEmpty());
        assertFalse(wac.allows(mallory, BASE + "/deleted", AclMode.WRITE));
    }

    /**
     * A <em>binary</em> resource keeps its bytes in the blob store and writes no named graph, so an
     * entry planted at {@code /c/.acl} leaves the server's real ACL sitting untouched at that name.
     * Quarantining on the entry alone would therefore discard a legitimate ACL and drop the
     * container to whatever an ancestor's {@code acl:default} allows — the migration turning into
     * the very escalation it exists to close.
     */
    @Test
    void aBinaryResourceOccupyingTheAclAddressDoesNotCostTheTargetItsAcl() {
        register(BASE + "/private/");
        registerBinary(BASE + "/private/.acl");
        writeGraph(BASE + "/private/.acl", grant(BASE + "/private/", ALICE, ACL.Read, ACL.Write));

        LegacyAclMigration.migrate(store, config, registry);

        assertFalse(wac.getAclModel(BASE + "/private/").isEmpty(), "the real ACL must survive");
        assertTrue(wac.allows(alice, BASE + "/private/", AclMode.WRITE));
        assertFalse(wac.allows(mallory, BASE + "/private/", AclMode.READ));
    }

    @Test
    void migrationIsIdempotent() {
        register(BASE + "/notes");
        writeGraph(BASE + "/notes.acl", grant(BASE + "/notes", ALICE, ACL.Read, ACL.Write));

        LegacyAclMigration.migrate(store, config, registry);
        Model afterFirst = wac.getAclModel(BASE + "/notes");
        LegacyAclMigration.migrate(store, config, registry);

        assertTrue(afterFirst.isIsomorphicWith(wac.getAclModel(BASE + "/notes")));
        assertTrue(wac.allows(alice, BASE + "/notes", AclMode.WRITE));
    }

    /** In owner mode the same store is only reported on — nothing may move. */
    @Test
    void reportChangesNothing() {
        register(BASE + "/notes");
        Model legacy = grant(BASE + "/notes", ALICE, ACL.Read, ACL.Write);
        writeGraph(BASE + "/notes.acl", legacy);

        LegacyAclMigration.report(store, config, registry);

        assertTrue(graph(BASE + "/notes.acl").isIsomorphicWith(legacy));
        assertTrue(wac.getAclModel(BASE + "/notes").isEmpty());
    }

    // ----- fixture helpers -----

    /** An authorization scoping {@code target} and granting {@code agent} the given modes. */
    private static Model grant(String target, String agent, Resource... modes) {
        Model m = ModelFactory.createDefaultModel();
        Resource a = m.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, m.createResource(target));
        a.addProperty(ACL.defaultAccess, m.createResource(target));
        a.addProperty(ACL.agent, m.createResource(agent));
        for (Resource mode : modes) {
            a.addProperty(ACL.mode, mode);
        }
        return m;
    }

    private void writeGraph(String name, Model model) {
        store.writeDo(conn -> conn.put(name, model));
    }

    private Model graph(String name) {
        return store.read(conn -> ModelFactory.createDefaultModel().add(conn.fetch(name)));
    }

    /** A binary resource: bytes in the blob store, so no named graph at its own IRI. */
    private void registerBinary(String iri) {
        Instant now = Instant.now();
        store.writeDo(conn -> registry.put(conn, new LwsResource(iri, ResourceType.NON_RDF_SOURCE,
                null, now, now, "etag", "application/octet-stream", 3, "ab/cd/abcd", ALICE, null)));
    }

    private void register(String iri) {
        Instant now = Instant.now();
        boolean container = iri.endsWith("/");
        store.writeDo(conn -> registry.put(conn, new LwsResource(iri,
                container ? ResourceType.CONTAINER : ResourceType.RDF_SOURCE,
                null, now, now, "etag", container ? null : "text/turtle", -1, null, ALICE, null)));
    }

    @Test
    void theAdvertisedAddressIsUnchangedByTheMove() {
        assertEquals(BASE + "/notes.acl", wac.aclIriFor(BASE + "/notes"));
        assertEquals(BASE + "/c/.acl", wac.aclIriFor(BASE + "/c/"));
    }
}
