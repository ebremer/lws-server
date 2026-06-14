package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Files;
import java.time.Clock;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Test;
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

    @Test
    void containerListingIsFilteredPerMemberReadAuthorization() throws Exception {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://example.org");
        p.setProperty("lws.data-dir", Files.createTempDirectory("lws-listing").toString());
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
                    .map(ResourceRegistry.ChildDesc::iri).toList();
            assertEquals(2, aliceSees.size());
            assertTrue(aliceSees.contains("http://example.org/c/secret"));

            // An anonymous client sees only the member it may read; the secret is omitted entirely.
            List<String> anonSees = service.read("/c/", null).children().stream()
                    .map(ResourceRegistry.ChildDesc::iri).toList();
            assertEquals(List.of("http://example.org/c/pub"), anonSees);
        } finally {
            rdf.close();
        }
    }
}
