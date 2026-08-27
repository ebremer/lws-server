package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.TestDirs;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;

/**
 * Verifies that a container listing is filtered per member by read authorization: a member the
 * requesting client cannot read is omitted entirely, and the listing is client-specific (lws10-core).
 *
 * @author Erich Bremer
 */
class ResourceServiceListingTest {

    /**
     * A fresh data directory per test. Deleted on the way out where the platform allows it, and by
     * the next run's sweep where it does not — see {@link TestDirs}.
     */
    private final Path tempDir = TestDirs.create();

    @Test
    void containerListingIsFilteredPerMemberReadAuthorization() throws Exception {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://example.org");
        // An owner, because this class asserts nothing about authorization and the
        // development posture now has to be asked for explicitly.
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        p.setProperty("lws.data-dir", tempDir.toString());
        LwsConfiguration config = LwsConfiguration.of(p);
        RdfStore rdf = new Tdb2RdfStore(config.tdb2Dir());
        try {
            // Allow everything except reading "/secret", which only Alice may read.
            Authorizer authorizer = (principal, iri, mode) -> {
                if (mode == AclMode.READ && iri.endsWith("/secret")) {
                    return principal != null && principal.webId().equals("http://example.org/alice");
                }
                return true;
            };
            ResourceService service = new ResourceService(rdf, new FileSystemBinaryStore(config.blobDir()),
                    new ResourceRegistry(), authorizer, config, Clock.systemUTC());
            service.ensureStorageRoot();

            LwsPrincipal alice = new LwsPrincipal("http://example.org/alice", null, null);
            service.create("/", alice,
                    new ResourceService.WriteRequest(null, new byte[0], ResourceService.TypeHint.CONTAINER, "c"));
            service.create("/c/", alice,
                    new ResourceService.WriteRequest("text/plain", "x".getBytes(), ResourceService.TypeHint.AUTO, "pub"));
            service.create("/c/", alice, new ResourceService.WriteRequest("text/plain", "x".getBytes(),
                    ResourceService.TypeHint.AUTO, "secret"));

            // Alice may read both members.
            List<String> aliceSees = service.read("/c/", alice).children().stream()
                    .map(ResourceRegistry.ChildRef::iri).toList();
            assertEquals(2, aliceSees.size());
            assertTrue(aliceSees.contains("http://example.org/c/secret"));

            // An anonymous client sees only the member it may read; the secret is omitted entirely.
            List<String> anonSees = service.read("/c/", null).children().stream()
                    .map(ResourceRegistry.ChildRef::iri).toList();
            assertEquals(List.of("http://example.org/c/pub"), anonSees);
        } finally {
            rdf.close();
        }
    }

    /**
     * The one case where "this principal may read everything" would be the wrong answer, and where
     * {@code DefaultAccessPolicy.permitsEveryResource} therefore has to say no.
     *
     * <p>Owner-based authorization has two kinds of owner: a WebID in {@code lws.owners}, which is a
     * fact about the storage, and a resource's own recorded {@code owner}, which is a fact about that
     * resource. Only the first is uniform. Alice here is neither a configured owner nor a controller —
     * she simply created some of the resources — so the per-member loop must still run, and the
     * listing she gets must still exclude what Bob created. Answering {@code true} for her would
     * disclose Bob's members, which is exactly the failure the optimization must not have.
     */
    @Test
    void aResourceOwnerWhoIsNotAConfiguredOwnerIsStillFilteredPerMember() throws Exception {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://example.org");
        p.setProperty("lws.owners", "https://storage-owner.example/#me");
        p.setProperty("lws.public-read", "false");
        p.setProperty("lws.data-dir", tempDir.toString());
        LwsConfiguration config = LwsConfiguration.of(p);
        RdfStore rdf = new Tdb2RdfStore(config.tdb2Dir());
        try {
            // The real policy, not a stub: this is a test about DefaultAccessPolicy's answer.
            Authorizer authorizer = new com.ebremer.lws.server.auth.OwnerAuthorizer(rdf,
                    new ResourceRegistry(), new com.ebremer.lws.server.auth.DefaultAccessPolicy(config));
            ResourceService service = new ResourceService(rdf, new FileSystemBinaryStore(config.blobDir()),
                    new ResourceRegistry(), authorizer, config, Clock.systemUTC());
            service.ensureStorageRoot();

            LwsPrincipal storageOwner = new LwsPrincipal("https://storage-owner.example/#me", null, null);
            LwsPrincipal alice = new LwsPrincipal("http://example.org/alice", null, null);
            LwsPrincipal bob = new LwsPrincipal("http://example.org/bob", null, null);
            // Registered directly, because the fixture is precisely "one container Alice owns, with
            // two members whose recorded owners differ" — and under this policy neither Alice nor Bob
            // could have created anything in a tree the storage owner owns.
            ResourceRegistry registry = new ResourceRegistry();
            rdf.writeDo(conn -> {
                registry.put(conn, container("http://example.org/shared/", alice.webId()));
                registry.put(conn, member("http://example.org/shared/alices", alice.webId()));
                registry.put(conn, member("http://example.org/shared/bobs", bob.webId()));
            });

            assertFalse(authorizer.allowsEverything(alice, AclMode.READ),
                    "a resource-owner's read permission is per resource and must not be claimed uniform");
            List<String> aliceSees = service.read("/shared/", alice).children().stream()
                    .map(ResourceRegistry.ChildRef::iri).toList();
            assertEquals(List.of("http://example.org/shared/alices"), aliceSees,
                    "Alice sees what she owns and not what Bob owns");

            // And the configured owner, whose answer IS uniform, sees both.
            assertTrue(authorizer.allowsEverything(storageOwner, AclMode.READ));
            assertEquals(2, service.read("/shared/", storageOwner).children().size());
        } finally {
            rdf.close();
        }
    }

    /** A registered container with an explicit recorded owner. */
    private static LwsResource container(String iri, String owner) {
        java.time.Instant now = java.time.Instant.now();
        return new LwsResource(iri, ResourceType.CONTAINER, "http://example.org/", now, now,
                Etags.of(iri, now.toString()), null, -1, null, owner, null);
    }

    /** A registered member of {@code /shared/} with an explicit recorded owner. */
    private static LwsResource member(String iri, String owner) {
        java.time.Instant now = java.time.Instant.now();
        return new LwsResource(iri, ResourceType.NON_RDF_SOURCE, "http://example.org/shared/", now, now,
                Etags.of(iri, now.toString()), "text/plain", 1, "k/" + owner.hashCode(), owner, null);
    }
}
