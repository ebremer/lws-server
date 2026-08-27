package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Properties;
import org.apache.jena.query.DatasetFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;

/**
 * The request router diverts {@code .acl}, {@code .meta}, the system prefix and the console and
 * login trees — but until finding C2 the <em>create</em> path did not, so a client could mint a
 * resource at any of those names. At best the result was unreachable by every HTTP method
 * (finding H18); at worst, before ACL graphs moved out of the public IRI space, {@code POST} with
 * {@code Slug: .acl} wrote the graph governing access to the container it was posted to.
 *
 * @author Erich Bremer
 */
class ReservedNameTest {

    private static final String BASE = "http://example.org";
    private static final LwsPrincipal ALICE = new LwsPrincipal("https://alice.example/#me", null, null);

    private LwsConfiguration config;
    private RdfStore store;
    private ResourceService service;

    @BeforeEach
    void setUp(@TempDir Path dir) throws Exception {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        // An owner, because this class asserts nothing about authorization and the
        // development posture now has to be asked for explicitly.
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        p.setProperty("lws.data-dir", dir.toString());
        config = LwsConfiguration.of(p);
        store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        service = new ResourceService(store, new FileSystemBinaryStore(config.blobDir()),
                new ResourceRegistry(), (principal, iri, mode) -> true, config, Clock.systemUTC());
        service.ensureStorageRoot();
        service.create("/", ALICE, container("c"));
    }

    // ----- the predicate -----

    @Test
    void reservesEveryNamespaceTheRouterDivertsAndNothingElse() {
        for (String reserved : new String[] {
                "/.acl", "/x.acl", "/c/x.acl", "/c/.acl", "/c/x.acl/", "/c/.acl/", "/..acl",
                "/.meta", "/x.meta", "/c/.meta", "/c/x.meta/",
                "/.lws", "/.lws/", "/.lws/storage-description",
                "/app", "/app/", "/app/oidc-login", "/callback", "/callback/x",
                // Reserved whether or not TLS automation is currently on: a name that becomes
                // shadowed the day an operator enables it is a name no resource should have taken.
                "/.well-known/acme-challenge", "/.well-known/acme-challenge/token",
                // Case-insensitively, because over-reserving is free and under-reserving is the bug.
                "/x.ACL", "/c/x.Meta", "/APP/x",
                // Anchored the way Iris.toIri anchors it, so a caller that omits the leading slash
                // is measured against the IRI its path would actually mint.
                "app", "callback", "x.acl" }) {
            assertTrue(config.isReservedPath(reserved), reserved + " must be reserved");
        }
        for (String allowed : new String[] {
                "/", "/c/", "/c/victim", "/x.acl-2", "/r-1a2b3c4d", "/notes.txt",
                // Only the absolute /app and /callback are shadowed; a segment at depth is not.
                "/c/app", "/c/callback", "/c/.lws", "/.well-known/", "/.well-known/other",
                // Percent-encoded forms are distinct IRIs to the router too, so the guard must not
                // decode: it tests the very string that becomes the resource IRI.
                "/c/x%2Eacl" }) {
            assertFalse(config.isReservedPath(allowed), allowed + " must not be reserved");
        }
    }

    /** Whatever the router hides, the guard must cover — the asymmetry that made C2 possible. */
    @Test
    void theReservedSetIsASupersetOfWhatTheRouterDivertsAway() {
        for (String path : new String[] { "/.acl", "/c/x.acl", "/.meta", "/c/x.meta", "/.lws",
                "/.lws/jwks", "/x.ACL" }) {
            boolean diverted = Iris.isAclPath(path) || Iris.isLinksetPath(path) || config.isSystemPath(path);
            assertTrue(!diverted || config.isReservedPath(path), path + " is diverted but not reserved");
        }
    }

    // ----- create -----

    @Test
    void refusesToCreateAResourceAtTheRootAclAddress() {
        assertEquals(409, conflictFrom(() -> service.create("/", ALICE, rdf(".acl"))));
        assertEquals(409, conflictFrom(() -> service.create("/c/", ALICE, rdf(".acl"))));
    }

    /** The sibling-seizure variant: an own-ACL outranks inheritance, so this one was the sharpest. */
    @Test
    void refusesToCreateAResourceAtAnotherResourcesAclAddress() {
        assertEquals(409, conflictFrom(() -> service.create("/c/", ALICE, rdf("victim.acl"))));
    }

    /** Finding H18: {@code .meta} minted a resource every HTTP method routes away from. */
    @Test
    void refusesToCreateAResourceAtALinksetAddress() {
        assertEquals(409, conflictFrom(() -> service.create("/c/", ALICE, rdf("report.meta"))));
        assertEquals(409, conflictFrom(() -> service.create("/c/", ALICE, rdf(".meta"))));
    }

    /** Finding L17: the console and login trees are occupied by filters, not by the resource API. */
    @Test
    void refusesToCreateAResourceShadowedByTheConsoleOrTheSystemPrefix() {
        assertEquals(409, conflictFrom(() -> service.create("/", ALICE, rdf("app"))));
        assertEquals(409, conflictFrom(() -> service.create("/", ALICE, container("app"))));
        assertEquals(409, conflictFrom(() -> service.create("/", ALICE, rdf("callback"))));
        assertEquals(409, conflictFrom(() -> service.create("/", ALICE, rdf(".lws"))));
        // ... but only at the root, where the filter mapping actually is.
        assertDoesNotThrow(() -> service.create("/c/", ALICE, rdf("app")));
    }

    /**
     * The check runs on the sanitized, composed path. Sanitizing can <em>create</em> a reserved
     * name — {@code x.acl-} and {@code .acl/} both collapse onto one — so testing the raw Slug
     * header would miss exactly the inputs an attacker would reach for.
     */
    @Test
    void refusesASlugThatOnlyBecomesReservedAfterSanitizing() {
        assertEquals(409, conflictFrom(() -> service.create("/c/", ALICE, rdf("x.acl-"))));
        assertEquals(409, conflictFrom(() -> service.create("/c/", ALICE, rdf("x.acl--"))));
        assertEquals(409, conflictFrom(() -> service.create("/c/", ALICE, rdf(".acl/"))));
    }

    /** And does not over-reach: ordinary dotted names, and forms that only look reserved, still work. */
    @Test
    void ordinaryNamesAreUnaffected() {
        assertDoesNotThrow(() -> service.create("/c/", ALICE, rdf("doc.json")));
        assertDoesNotThrow(() -> service.create("/c/", ALICE, rdf("notes.metadata")));
        assertDoesNotThrow(() -> service.create("/c/", ALICE, rdf("%2Eacl")));
        assertDoesNotThrow(() -> service.create("/c/", ALICE, rdf(null))); // generated name
    }

    // ----- put -----

    @Test
    void refusesToPutAtAReservedPath() {
        assertEquals(409, conflictFrom(() -> service.put("/c/x.acl", ALICE, rdf(null))));
        assertEquals(409, conflictFrom(() -> service.put("/c/x.meta", ALICE, rdf(null))));
        assertEquals(409, conflictFrom(() -> service.put("/c/.acl", ALICE, rdf(null))));
        assertEquals(409, conflictFrom(() -> service.put("/.lws/thing", ALICE, rdf(null))));
        assertEquals(409, conflictFrom(() -> service.put("/app/thing", ALICE, rdf(null))));
        assertEquals(409, conflictFrom(() -> service.put("/callback", ALICE, rdf(null))));
    }

    /**
     * A store built before the reservation can already hold such a resource, so the replace branch
     * must refuse too — otherwise a {@code PUT} over a legacy {@code /c/x.acl} would keep writing
     * the graph the ACL used to be read from.
     */
    @Test
    void refusesToPutOverALegacyResourceAtAReservedPath() {
        String iri = BASE + "/c/legacy.acl";
        ResourceRegistry registry = new ResourceRegistry();
        java.time.Instant now = java.time.Instant.now();
        store.writeDo(conn -> registry.put(conn, new LwsResource(iri, ResourceType.RDF_SOURCE,
                BASE + "/c/", now, now, "etag", "text/turtle", -1, null, ALICE.webId(), null)));
        assertTrue(service.stat("/c/legacy.acl").isPresent(), "the legacy resource must exist for this test");

        assertEquals(409, conflictFrom(() -> service.put("/c/legacy.acl", ALICE, rdf(null))));
    }

    private static int conflictFrom(Runnable action) {
        return assertThrows(LwsException.class, action::run).status();
    }

    private static ResourceService.WriteRequest rdf(String slug) {
        return new ResourceService.WriteRequest("text/turtle", new byte[0],
                ResourceService.TypeHint.AUTO, slug);
    }

    private static ResourceService.WriteRequest container(String slug) {
        return new ResourceService.WriteRequest(null, new byte[0],
                ResourceService.TypeHint.CONTAINER, slug);
    }
}
