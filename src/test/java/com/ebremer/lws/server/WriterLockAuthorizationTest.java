package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Properties;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.ebremer.lws.server.auth.DocumentLoader;
import com.ebremer.lws.server.auth.WacAclService;
import com.ebremer.lws.server.core.IfMatch;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;
import com.ebremer.lws.server.vocab.ACL;
import com.ebremer.lws.server.vocab.VCARD;

/**
 * The metadata store admits a single writer for the whole dataset, so nothing that can block
 * indefinitely may run inside a write transaction. Web Access Control resolves
 * {@code acl:agentGroup} membership by dereferencing the group document — at an address the
 * requester's own ACL names — so every {@link ResourceService} operation resolves its authorization
 * inputs through {@code Authorizer.prepare} before the transaction opens, leaving the decision
 * itself inside it, authoritative and local (H16).
 *
 * @author Erich Bremer
 */
class WriterLockAuthorizationTest {

    private static final String BASE = "http://example.org";
    private static final String ALICE = "https://alice.example/profile#me";
    private static final String BOB = "https://bob.example/profile#me";
    private static final String GROUP = "https://groups.example/team";

    /** Records every fetch, and above all whether any of them happened under the writer lock. */
    private static final class WatchfulLoader implements DocumentLoader {

        private final RdfStore store;
        private int calls;
        private boolean fetchedInsideTransaction;

        WatchfulLoader(RdfStore store) {
            this.store = store;
        }

        @Override
        public String load(String url) {
            return null;
        }

        @Override
        public Model loadRdf(String url) {
            calls++;
            if (store.inUnitOfWork()) {
                fetchedInsideTransaction = true;
            }
            Model doc = ModelFactory.createDefaultModel();
            doc.createResource(GROUP).addProperty(VCARD.hasMember, doc.createResource(BOB));
            return doc;
        }
    }

    @Test
    void everyWritePathResolvesGroupMembershipBeforeOpeningItsTransaction(@TempDir Path dir) throws Exception {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.data-dir", dir.toString());
        p.setProperty("lws.access-control", "wac");
        p.setProperty("lws.owners", ALICE);
        LwsConfiguration config = LwsConfiguration.of(p);

        RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        try {
            WatchfulLoader loader = new WatchfulLoader(store);
            WacAclService wac = new WacAclService(store, config, loader);
            ResourceService service = new ResourceService(store, new FileSystemBinaryStore(config.blobDir()),
                    new ResourceRegistry(), wac, config, Clock.systemUTC());
            service.ensureStorageRoot();

            // The whole storage is governed by one ACL that grants the group Read + Write, so every
            // operation below has to resolve the group document to reach a decision.
            Model acl = ModelFactory.createDefaultModel();
            Resource a = acl.createResource();
            a.addProperty(RDF.type, ACL.Authorization);
            a.addProperty(ACL.accessTo, acl.createResource(config.storageRootIri()));
            a.addProperty(ACL.defaultAccess, acl.createResource(config.storageRootIri()));
            a.addProperty(ACL.agentGroup, acl.createResource(GROUP));
            a.addProperty(ACL.mode, ACL.Read);
            a.addProperty(ACL.mode, ACL.Write);
            wac.putSystemAclFor(config.storageRootIri(), acl);

            LwsPrincipal bob = new LwsPrincipal(BOB, "iss", null);

            // One of every write path, plus a read, so each one's warm-up is exercised.
            service.create("/", bob, new ResourceService.WriteRequest(null, new byte[0],
                    ResourceService.TypeHint.CONTAINER, "tree"));
            service.create("/tree/", bob, new ResourceService.WriteRequest("application/json",
                    "{}".getBytes(), ResourceService.TypeHint.AUTO, "leaf"));
            // Replacing an existing resource must name the version it replaces (M20), so this one
            // reads the tag first, exactly as a real client does.
            service.put("/tree/leaf", bob, new ResourceService.WriteRequest("application/json",
                    "{}".getBytes(), ResourceService.TypeHint.AUTO, null),
                    IfMatch.of("\"" + service.stat("/tree/leaf").orElseThrow().etag() + "\""));
            // PATCH names the version it changes too, so each of these reads the tag first
            // (prior-review finding 14).
            service.patch("/tree/leaf", bob, "{\"a\":1}".getBytes(), "application/merge-patch+json",
                    currentTag(service, "/tree/leaf"));
            service.patch("/tree/leaf", bob, "[{\"op\":\"add\",\"path\":\"/b\",\"value\":2}]".getBytes(),
                    "application/json-patch+json", currentTag(service, "/tree/leaf"));
            service.put("/tree/note", bob, new ResourceService.WriteRequest("text/turtle",
                    "<> <http://schema.org/name> \"n\" .".getBytes(), ResourceService.TypeHint.AUTO, null));
            service.patch("/tree/note", bob,
                    "INSERT DATA { <http://example.org/tree/note> <http://schema.org/x> 1 }".getBytes(),
                    "application/sparql-update", currentTag(service, "/tree/note"));
            assertTrue(service.read("/tree/", bob).isContainer());
            service.delete("/tree/", bob, true); // recursive: authorizes every descendant

            assertFalse(loader.fetchedInsideTransaction,
                    "a group document was dereferenced while the writer lock was held");
            assertTrue(loader.calls > 0, "the test is only meaningful if the group was resolved at all");
            // Warmed once, then served from cache for the whole run.
            assertEquals(1, loader.calls);
        } finally {
            store.close();
        }
    }

    /** The current entity-tag of a resource, wrapped as an If-Match precondition. */
    private static IfMatch currentTag(ResourceService service, String path) {
        return IfMatch.of("\"" + service.stat(path).orElseThrow().etag() + "\"");
    }
}
