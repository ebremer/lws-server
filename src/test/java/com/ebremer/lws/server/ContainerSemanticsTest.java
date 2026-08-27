package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * A write that cannot be carried out is refused, rather than accepted and quietly discarded
 * (findings M13, M14, M38 and H21).
 *
 * <p>All four are the same failure in different clothes: the server answers {@code 201}/{@code 204}
 * with a fresh entity-tag, and the thing the client actually asked for did not happen. A container
 * PUT drops the body; a container type hint on a slash-less path mints a resource its own parent
 * cannot list; a TriG body loses every named-graph quad; a merge-patch on a two-subject RDF resource
 * destroys the graph. In each case the client's next {@code GET} is its only evidence, and by then
 * the old version is gone.
 *
 * @author Erich Bremer
 */
class ContainerSemanticsTest {

    /**
     * This class's data directory. Deleted on the way out where the platform allows it, and by the
     * next run's sweep where it does not — see {@link TestDirs}. It used to be a bare
     * {@code createTempDirectory} that nothing ever removed, and the leak once filled a disk.
     */
    private static final Path tempDir = TestDirs.create();

    private static final String CONTAINER_LINK = "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"";

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        baseUrl = "http://localhost:" + port;
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        // Open mode: this class asserts protocol behaviour, not authorization outcomes,
        // so it opts in to the development posture rather than configuring an owner.
        p.setProperty("lws.dev.open", "true");
        p.setProperty("lws.data-dir", tempDir.toString());
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
        http = HttpClient.newHttpClient();
    }

    @AfterAll
    static void stop() throws Exception {
        if (server != null) {
            server.stop();
        }
        if (components != null) {
            components.close();
        }
    }

    // ----- M14: PUT with a body to an existing container -----

    @Test
    void puttingABodyToAnExistingContainerIsRefusedRatherThanDiscarded() throws Exception {
        assertEquals(201, send("PUT", "/m14/", null, "Link", CONTAINER_LINK).statusCode());
        String before = etagOf("/m14/");

        HttpResponse<String> put = send("PUT", "/m14/", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle", "If-Match", before);
        assertEquals(409, put.statusCode(),
                "a container's representation is its membership; there is nowhere to put these triples");
        assertEquals(before, etagOf("/m14/"), "a refused write must not mint a new version");
    }

    @Test
    void puttingAnEmptyBodyToAnExistingContainerStoresNothingAndMintsNoNewVersion() throws Exception {
        assertEquals(201, send("PUT", "/m14b/", null, "Link", CONTAINER_LINK).statusCode());
        String before = etagOf("/m14b/");

        assertEquals(204, send("PUT", "/m14b/", null, "Link", CONTAINER_LINK, "If-Match", before).statusCode());

        assertEquals(before, etagOf("/m14b/"),
                "nothing was stored, so the entity-tag must not move — a client that re-read it "
                        + "and conditioned on the old value would otherwise get a permanent 412");
    }

    // ----- M13: a type hint that contradicts the path -----

    @Test
    void aContainerHintOnASlashLessPathIsRefused() throws Exception {
        assertEquals(400, send("PUT", "/m13", null, "Link", CONTAINER_LINK).statusCode(),
                "a container IRI ends in '/'; registering one at a slash-less IRI breaks parentPath");
        assertEquals(404, send("GET", "/m13", null).statusCode(), "and nothing may be created");
    }

    @Test
    void aNonContainerHintOnAContainerPathIsRefused() throws Exception {
        assertEquals(400, send("PUT", "/m13b/", "hi", "Content-Type", "text/plain",
                "Link", "<http://www.w3.org/ns/ldp#NonRDFSource>; rel=\"type\"").statusCode());
    }

    /**
     * A contradictory hint is a contradictory request whether or not anything is stored there, so the
     * check runs ahead of the rule that a container cannot be replaced — otherwise an existing
     * container would quietly absorb a {@code NonRDFSource} hint that a missing one refuses.
     */
    @Test
    void aContradictoryHintIsRefusedOnAnExistingContainerToo() throws Exception {
        assertEquals(201, send("PUT", "/m13d/", null, "Link", CONTAINER_LINK).statusCode());
        String etag = etagOf("/m13d/");
        assertEquals(400, send("PUT", "/m13d/", null, "If-Match", etag,
                "Link", "<http://www.w3.org/ns/ldp#NonRDFSource>; rel=\"type\"").statusCode());
        assertEquals(etag, etagOf("/m13d/"));
    }

    /** POST is unaffected: it composes the trailing slash itself, so the hint is honoured. */
    @Test
    void postingAContainerHintStillCreatesAContainer() throws Exception {
        assertEquals(201, send("PUT", "/m13c/", null, "Link", CONTAINER_LINK).statusCode());
        HttpResponse<String> post = send("POST", "/m13c/", null, "Link", CONTAINER_LINK, "Slug", "inner");
        assertEquals(201, post.statusCode());
        assertEquals(baseUrl + "/m13c/inner/", post.headers().firstValue("Location").orElseThrow());
        assertEquals(200, send("GET", "/m13c/inner/", null).statusCode());
    }

    /**
     * The container rule is about containers, not about one branch of {@code put}: creating one with
     * a body discards it exactly as replacing one did, and answers {@code 201} with a fresh tag.
     */
    @Test
    void creatingAContainerWithABodyIsRefused() throws Exception {
        assertEquals(409, send("PUT", "/m14c/", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle", "Link", CONTAINER_LINK).statusCode());
        assertEquals(404, send("GET", "/m14c/", null).statusCode());

        assertEquals(201, send("PUT", "/m14d/", null, "Link", CONTAINER_LINK).statusCode());
        assertEquals(409, send("POST", "/m14d/", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle", "Link", CONTAINER_LINK, "Slug", "inner").statusCode());
        assertEquals(404, send("GET", "/m14d/inner/", null).statusCode());
    }

    // ----- M38: quads that a Model cannot hold -----

    @Test
    void trigCarryingANamedGraphIsRefusedRatherThanTruncated() throws Exception {
        String trig = "<#it> <http://schema.org/name> \"default\" .\n"
                + "GRAPH <http://example.org/g1> { <#it> <http://schema.org/secret> \"hidden\" . }\n";
        assertEquals(400, send("PUT", "/m38", trig, "Content-Type", "application/trig").statusCode(),
                "every quad outside the default graph would be dropped on the floor");
        assertEquals(404, send("GET", "/m38", null).statusCode());
    }

    @Test
    void trigCarryingOnlyDefaultGraphDataIsStillAccepted() throws Exception {
        assertEquals(201, send("PUT", "/m38b", "<#it> <http://schema.org/name> \"kept\" .",
                "Content-Type", "application/trig").statusCode());
        assertTrue(send("GET", "/m38b", null, "Accept", "text/turtle").body().contains("kept"));
    }

    /**
     * The same rule has to hold for the update language, or H21 has merely redirected clients from
     * one silent-loss path onto another: a resource is a single graph, so a SPARQL Update that names
     * a different one cannot be carried out. Measured before this was refused: {@code INSERT DATA}
     * into a named graph left the model untouched, threw nothing, and answered {@code 204}.
     */
    @Test
    void sparqlUpdateNamingAGraphIsRefused() throws Exception {
        assertEquals(201, send("PUT", "/m38c", "<#it> <http://schema.org/name> \"v1\" .",
                "Content-Type", "text/turtle").statusCode());
        String etag = etagOf("/m38c");

        assertEquals(400, send("PATCH", "/m38c",
                "INSERT DATA { GRAPH <http://example.org/g1> { <#it> <http://schema.org/x> 1 } }",
                "Content-Type", "application/sparql-update", "If-Match", etag).statusCode());
        assertEquals(400, send("PATCH", "/m38c",
                "WITH <http://example.org/g1> DELETE { ?s ?p ?o } WHERE { ?s ?p ?o }",
                "Content-Type", "application/sparql-update", "If-Match", etag).statusCode());
        assertEquals(400, send("PATCH", "/m38c",
                "DELETE { ?s ?p ?o } WHERE { GRAPH <http://example.org/g1> { ?s ?p ?o } }",
                "Content-Type", "application/sparql-update", "If-Match", etag).statusCode());

        // The sharp case: a mixed body. The default-graph half would apply and be stored, the GRAPH
        // half would be lost, and the response would carry a NEW and perfectly valid entity-tag over
        // the partially-applied model — partial application indistinguishable from full success.
        assertEquals(400, send("PATCH", "/m38c",
                "INSERT DATA { <#it> <http://schema.org/a> 1 . "
                        + "GRAPH <http://example.org/g1> { <#it> <http://schema.org/b> 2 } }",
                "Content-Type", "application/sparql-update", "If-Match", etag).statusCode());

        // And the one a client is most likely to write by accident: naming its own resource, which
        // this storage does hold as a named graph — but which is the default graph of the model the
        // update runs against, so it was a silent no-op rather than the obvious thing.
        assertEquals(400, send("PATCH", "/m38c",
                "INSERT DATA { GRAPH <" + baseUrl + "/m38c> { <#it> <http://schema.org/c> 3 } }",
                "Content-Type", "application/sparql-update", "If-Match", etag).statusCode());

        assertEquals(etag, etagOf("/m38c"), "a refused update must not mint a new version");
        assertTrue(send("GET", "/m38c", null, "Accept", "text/turtle").body().contains("v1"));
        assertFalse(send("GET", "/m38c", null, "Accept", "text/turtle").body().contains("schema.org/a"),
                "no half of a refused mixed update may have landed");
    }

    // ----- H21: JSON Merge Patch over RDF -----

    @Test
    void mergePatchOnAnRdfResourceIsRefusedAndDestroysNothing() throws Exception {
        String twoSubjects = "<> <http://schema.org/name> \"Alice\" ; <http://schema.org/about> <#it> .\n"
                + "<#it> <http://schema.org/description> \"about me\" .\n";
        assertEquals(201, send("PUT", "/h21", twoSubjects, "Content-Type", "text/turtle").statusCode());
        String etag = etagOf("/h21");

        assertEquals(415, send("PATCH", "/h21", "{\"http://schema.org/keywords\":\"rdf\"}",
                "Content-Type", "application/merge-patch+json", "If-Match", etag).statusCode());

        // The whole graph survives. Before this was refused, the patch replaced all three triples
        // with a single one on a fresh blank node, and answered 204.
        String after = send("GET", "/h21", null, "Accept", "text/turtle").body();
        assertTrue(after.contains("Alice"), after);
        assertTrue(after.contains("about me"), after);
        assertEquals(etag, etagOf("/h21"), "a refused patch must not mint a new version");
    }

    @Test
    void rdfResourcesDoNotAdvertiseMergePatch() throws Exception {
        assertEquals(201, send("PUT", "/h21b", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());
        String acceptPatch = send("GET", "/h21b", null).headers().firstValue("Accept-Patch").orElseThrow();
        assertTrue(acceptPatch.contains("application/sparql-update"), acceptPatch);
        assertFalse(acceptPatch.contains("merge-patch"),
                "advertising an operation that cannot work on RDF is what got it used: " + acceptPatch);
    }

    /** SPARQL Update remains the way to patch an RDF resource, and still works. */
    @Test
    void sparqlUpdatePatchStillWorksOnRdf() throws Exception {
        assertEquals(201, send("PUT", "/h21c", "<#it> <http://schema.org/name> \"before\" .",
                "Content-Type", "text/turtle").statusCode());
        String etag = etagOf("/h21c");
        assertEquals(204, send("PATCH", "/h21c",
                "DELETE { ?s <http://schema.org/name> \"before\" } "
                        + "INSERT { ?s <http://schema.org/name> \"after\" } WHERE { ?s ?p ?o }",
                "Content-Type", "application/sparql-update", "If-Match", etag).statusCode());
        assertTrue(send("GET", "/h21c", null, "Accept", "text/turtle").body().contains("after"));
    }

    /** Merge patch keeps working where it is well defined: an opaque JSON resource. */
    @Test
    void mergePatchStillWorksOnAJsonResource() throws Exception {
        assertEquals(201, send("PUT", "/h21d", "{\"n\":1}", "Content-Type", "application/json").statusCode());
        String etag = etagOf("/h21d");
        assertEquals(204, send("PATCH", "/h21d", "{\"n\":2}",
                "Content-Type", "application/merge-patch+json", "If-Match", etag).statusCode());
        assertTrue(send("GET", "/h21d", null).body().contains("\"n\":2"));
    }

    // ----- helpers -----

    private static String etagOf(String path) throws Exception {
        HttpResponse<String> r = send("GET", path, null);
        assertEquals(200, r.statusCode(), path);
        return r.headers().firstValue("ETag").orElseThrow(() -> new AssertionError("no ETag on " + path));
    }

    // ----- M15: a colliding Slug costs a bounded number of probes, not an unbounded scan -----

    /**
     * Repeating one {@code Slug} produces {@code dup}, {@code dup-2} … {@code dup-8}, and then stops
     * counting: the ninth and later get a random suffix.
     *
     * <p>The names are the observable half of the fix. The half that matters is what they cost: the
     * de-duplication was an uncapped linear scan issuing one {@code ASK} per iteration <em>inside the
     * global write transaction</em>, so the Nth POST held the storage's single writer for N queries
     * and the sequence as a whole was quadratic — ten thousand POSTs of one {@code Slug} cost about
     * fifty million {@code ASK}s (finding M15). Against the pre-fix code the ninth resource is
     * created at {@code /m15/dup-9} and the first assertion below fails.
     *
     * <p>Every name is distinct, so nothing was silently overwritten — which is the failure mode a
     * random suffix would have if it were trusted rather than probed:
     * {@code ResourceRegistry.put} is a delete-then-load.
     */
    @Test
    void aRepeatedSlugStopsCountingAndRandomizes() throws Exception {
        assertEquals(201, send("PUT", "/m15/", null, "Link", CONTAINER_LINK).statusCode());
        java.util.List<String> created = new java.util.ArrayList<>();
        for (int i = 0; i < 12; i++) {
            HttpResponse<String> r = send("POST", "/m15/", "x", "Slug", "dup", "Content-Type", "text/plain");
            assertEquals(201, r.statusCode(), "POST " + i);
            created.add(r.headers().firstValue("Location").orElseThrow());
        }
        assertEquals(baseUrl + "/m15/dup", created.get(0));
        for (int n = 2; n <= 8; n++) {
            assertEquals(baseUrl + "/m15/dup-" + n, created.get(n - 1), "sequential probe " + n);
        }
        for (int i = 8; i < 12; i++) {
            String name = created.get(i).substring((baseUrl + "/m15/").length());
            assertTrue(name.matches("dup-[0-9a-f]{8}"),
                    "the 9th and later get a random suffix, not dup-" + (i + 1) + ": " + name);
        }
        assertEquals(12, new java.util.HashSet<>(created).size(), "no name was reused");
        // Every one of them really is there: a random suffix is probed before it is used, so this
        // would fail if a collision had silently replaced an earlier resource's metadata.
        for (String iri : created) {
            assertEquals(200, send("GET", iri.substring(baseUrl.length()), null).statusCode(), iri);
        }
    }

    /** A Slug that sanitizes into a reserved name is still refused, on the randomized path too. */
    @Test
    void aReservedSlugIsRefusedRatherThanRenamed() throws Exception {
        assertEquals(201, send("PUT", "/m15r/", null, "Link", CONTAINER_LINK).statusCode());
        assertEquals(409, send("POST", "/m15r/", "x", "Slug", "notes.acl", "Content-Type", "text/plain")
                .statusCode());
    }

    private static HttpResponse<String> send(String method, String path, String body, String... headers)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path));
        for (int i = 0; i + 1 < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
