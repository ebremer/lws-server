package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.charset.StandardCharsets;
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
 * Replacing an existing resource must name the version it replaces, whoever is asking (finding
 * M20).
 *
 * <p>The rule used to live only in {@code LwsResourceServlet}, so it governed the HTTP API and
 * nothing else. The Wicket console calls {@link ResourceService} directly and was therefore exempt:
 * two console users editing the same resource each read it, each saved, and the second silently
 * discarded the first while the UI reported "Saved." A rule that only one of two entry points
 * enforces is not a rule, so it moved to the object both of them go through.
 *
 * @author Erich Bremer
 */
class MandatoryPreconditionTest {

    private static final String BASE = "http://example.org";
    private static final LwsPrincipal ALICE = new LwsPrincipal("https://alice.example/#me", null, null);

    private ResourceService service;

    @BeforeEach
    void setUp(@TempDir Path dir) throws Exception {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        // An owner, because this class asserts nothing about authorization and the
        // development posture now has to be asked for explicitly.
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        p.setProperty("lws.data-dir", dir.toString());
        LwsConfiguration config = LwsConfiguration.of(p);
        RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        service = new ResourceService(store, new FileSystemBinaryStore(config.blobDir()),
                new ResourceRegistry(), (principal, iri, mode) -> true, config, Clock.systemUTC());
        service.ensureStorageRoot();
    }

    @Test
    void creatingIsUnconditional() {
        ResourceService.PutOutcome out = service.put("/new", ALICE, rdf("v1"), IfMatch.NONE);
        assertTrue(out.created());
    }

    @Test
    void replacingWithoutAPreconditionIsRefused() {
        service.put("/doc", ALICE, rdf("v1"), IfMatch.NONE);

        LwsException e = assertThrows(LwsException.class,
                () -> service.put("/doc", ALICE, rdf("v2"), IfMatch.NONE));
        assertEquals(428, e.status(), e.getMessage());

        assertTrue(read("/doc").contains("v1"), "the refused write must not have landed");
    }

    @Test
    void replacingWithTheCurrentTagSucceedsAndWithAStaleOneDoesNot() {
        service.put("/doc", ALICE, rdf("v1"), IfMatch.NONE);
        String first = service.stat("/doc").orElseThrow().etag();

        service.put("/doc", ALICE, rdf("v2"), IfMatch.of("\"" + first + "\""));
        assertTrue(read("/doc").contains("v2"));

        // The tag the first editor is still holding is now stale: its save is refused rather than
        // silently discarding the second editor's work.
        LwsException e = assertThrows(LwsException.class,
                () -> service.put("/doc", ALICE, rdf("v3"), IfMatch.of("\"" + first + "\"")));
        assertEquals(412, e.status(), e.getMessage());
        assertTrue(read("/doc").contains("v2"));
    }

    /** The two-editor race the finding describes, driven through the service the console uses. */
    @Test
    void twoEditorsHoldingTheSameTagCannotBothSave() {
        service.put("/notes", ALICE, rdf("original"), IfMatch.NONE);
        String shared = "\"" + service.stat("/notes").orElseThrow().etag() + "\"";

        service.put("/notes", ALICE, rdf("editor-one"), IfMatch.of(shared));
        LwsException e = assertThrows(LwsException.class,
                () -> service.put("/notes", ALICE, rdf("editor-two"), IfMatch.of(shared)));

        assertEquals(412, e.status());
        assertTrue(read("/notes").contains("editor-one"),
                "the first save stands; the second is told, not silently dropped");
    }

    // ----- helpers -----

    private String read(String path) {
        return service.read(path, ALICE).rdf().toString();
    }

    private static ResourceService.WriteRequest rdf(String name) {
        String turtle = "<" + BASE + "/#it> <http://schema.org/name> \"" + name + "\" .";
        return new ResourceService.WriteRequest("text/turtle", turtle.getBytes(StandardCharsets.UTF_8),
                ResourceService.TypeHint.RDF_SOURCE, null);
    }
}
