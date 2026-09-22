package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * HTTP integration tests for the Type Index and Type Search services (lws10-index), driving a live
 * server in open mode: service discovery, the type index, the QUERY type search (single, OR, AND,
 * container and relation filters, the filter grammar's edge cases, page links), and the specified
 * error responses.
 *
 * @author Erich Bremer
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SearchIndexTest {

    /**
     * This class's data directory. Deleted on the way out where the platform allows it, and by the
     * next run's sweep where it does not — see {@link TestDirs}. It used to be a bare
     * {@code createTempDirectory} that nothing ever removed, and the leak once filled a disk.
     */
    private static final Path tempDir = TestDirs.create();

    private static final String SCHEMA_PERSON = "https://schema.org/Person";
    private static final String FOAF_PERSON = "http://xmlns.com/foaf/0.1/Person";
    private static final String SCHEMA_EVENT = "https://schema.org/Event";
    private static final String LWS_DATA = "https://www.w3.org/ns/lws#DataResource";
    private static final String LWS_CONTAINER = "https://www.w3.org/ns/lws#Container";
    private static final String SHAPE = "https://shapes.example/PersonShape";
    private static final String SHAPE_PRED = "https://ex.org/shape";

    private static final String INDEX = "/.lws/type-index";
    private static final String SEARCH = "/.lws/type-search";

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

        put("/alice", "<> a <" + SCHEMA_PERSON + "> ; <https://schema.org/name> \"Alice\" ; "
                + "<" + SHAPE_PRED + "> <" + SHAPE + "> .");
        put("/bob", "<> a <" + SCHEMA_PERSON + "> .");
        put("/carol", "<> a <" + FOAF_PERSON + "> .");
        put("/event1", "<> a <" + SCHEMA_EVENT + "> .");
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

    @Test
    void storageDescriptionAdvertisesBothServicesOnTheStorage() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/.lws/storage-description"))
                .header("Accept", "text/turtle").GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode());
        Model m = ModelFactory.createDefaultModel();
        RDFDataMgr.read(m, new ByteArrayInputStream(r.body().getBytes(StandardCharsets.UTF_8)),
                baseUrl + "/", Lang.TURTLE);
        // The storage description is a controlled identifier document, so the service objects hang
        // off the lws:Storage node by the CID context's `service`, each carrying its rdf:type and its
        // serviceEndpoint.
        assertTrue(serviceAdvertised(m, "TypeIndexService", baseUrl + INDEX), r.body());
        assertTrue(serviceAdvertised(m, "TypeSearchService", baseUrl + SEARCH), r.body());
    }

    private static boolean serviceAdvertised(Model model, String serviceType, String endpointIri) {
        String ask = ("""
                PREFIX lws: <https://www.w3.org/ns/lws#>
                PREFIX did: <https://www.w3.org/ns/did#>
                ASK {
                  ?storage a lws:Storage ; did:service [ a lws:%s ; did:serviceEndpoint ?endpoint ] .
                  FILTER( str(?endpoint) = "%s" )
                }""").formatted(serviceType, endpointIri);
        try (QueryExecution qe = QueryExecutionFactory.create(QueryFactory.create(ask), model)) {
            return qe.execAsk();
        }
    }

    @Test
    @Order(1)
    void typeIndexListsDistinctVisibleTypes() {
        JsonObject doc = getLws(baseUrl + INDEX);
        assertEquals("TypeIndex", doc.getString("type"));
        Set<String> types = ids(doc);
        assertEquals(Set.of(LWS_CONTAINER, LWS_DATA, SCHEMA_PERSON, SCHEMA_EVENT, FOAF_PERSON), types);
        assertEquals(types.size(), doc.getInt("totalItems"));
    }

    /**
     * Adds a type to a shared index and takes it away again, so the cleanup runs in a
     * {@code finally}: {@link #typeIndexListsDistinctVisibleTypes} asserts the <em>exact</em> set of
     * visible types, and an assertion failing here used to leave {@code Ephemeral} behind and fail
     * that one too — a second, misleading red for a defect in neither (finding M46).
     */
    @Test
    @Order(2)
    void derivedIndexReflectsCreateAndDelete() throws Exception {
        String type = "https://ex.org/Ephemeral";
        try {
            // A resource created while the derived index is in use must become searchable...
            put("/ephemeral", "<> a <" + type + "> .");
            assertTrue(ids(query(types(type))).contains(baseUrl + "/ephemeral"),
                    "a newly created resource must be searchable");
        } finally {
            // ...and deleting it must remove it from the index (incremental maintenance).
            delete("/ephemeral");
        }
        assertEquals(0, query(types(type)).getInt("totalItems"), "a deleted resource must leave the index");
    }

    /** A page reference the server does not recognize is 404 (lws10-index), for the index too. */
    @Test
    void typeIndexAnswersAnUnknownPageWithNotFound() throws Exception {
        assertEquals(404, status(baseUrl + INDEX + "?page=0"));
        assertEquals(404, status(baseUrl + INDEX + "?page=abc"));
        assertEquals(404, status(baseUrl + INDEX + "?page=99"));
    }

    @Test
    void searchSingleType() throws Exception {
        JsonObject doc = query(types(SCHEMA_PERSON));
        assertEquals("ContainerPage", doc.getString("type"));
        assertEquals(Set.of(baseUrl + "/alice", baseUrl + "/bob"), ids(doc));
    }

    @Test
    void searchOrWithinGroup() throws Exception {
        JsonObject doc = query("{ \"type\": [ [ \"" + SCHEMA_PERSON + "\", \"" + FOAF_PERSON + "\" ] ] }");
        assertEquals(Set.of(baseUrl + "/alice", baseUrl + "/bob", baseUrl + "/carol"), ids(doc));
    }

    @Test
    void searchAndAcrossGroups() throws Exception {
        JsonObject doc = query("{ \"type\": [ \"" + SCHEMA_PERSON + "\", \"" + LWS_DATA + "\" ] }");
        assertEquals(Set.of(baseUrl + "/alice", baseUrl + "/bob"), ids(doc));
    }

    @Test
    void searchByNativeContainerType() throws Exception {
        JsonObject doc = query(types(LWS_CONTAINER));
        assertEquals(Set.of(baseUrl + "/"), ids(doc));
    }

    /**
     * A filter document is plain JSON: an {@code @}-member is ignored, an empty value is no
     * constraint, duplicate groups count once — and a filter with no constraint at all matches every
     * resource the client may read (lws10-index).
     */
    @Test
    void filterGrammarEdgeCases() throws Exception {
        JsonObject all = query("{}");
        assertTrue(ids(all).containsAll(Set.of(baseUrl + "/", baseUrl + "/alice", baseUrl + "/event1")), all.toString());
        assertEquals(ids(all), ids(query("{ \"@context\": \"https://www.w3.org/ns/lws/v1\", \"type\": [] }")),
                "an @-member and an empty value constrain nothing");
        assertEquals(Set.of(baseUrl + "/alice", baseUrl + "/bob"),
                ids(query("{ \"type\": [ \"" + SCHEMA_PERSON + "\", \"" + SCHEMA_PERSON + "\" ] }")),
                "a duplicate group is ignored");
    }

    /** A URI-valued relation key matches the predicate the resource's own representation asserts. */
    @Test
    void searchByDescriptiveRelation() throws Exception {
        JsonObject doc = query("{ \"type\": [ \"" + SCHEMA_PERSON + "\" ], \"" + SHAPE_PRED + "\": [ \"" + SHAPE + "\" ] }");
        assertEquals(Set.of(baseUrl + "/alice"), ids(doc));
    }

    /**
     * A registered relation name matches the links a resource's metadata declares — the
     * lws10-index example's {@code describedby} — and a relation nothing declares, or that this
     * server does not index, yields no results rather than an error, indistinguishably.
     */
    @Test
    @Order(40)
    void searchByADeclaredRegisteredRelation() throws Exception {
        put("/dave", "<> a <" + SCHEMA_PERSON + "> .");
        String etag = getRaw(baseUrl + "/dave.meta").headers().firstValue("ETag").orElseThrow();
        HttpResponse<String> patched = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/dave.meta"))
                .header("Content-Type", "application/merge-patch+json").header("If-Match", etag)
                .method("PATCH", HttpRequest.BodyPublishers.ofString(
                        "{\"describedby\":[{\"href\":\"" + SHAPE + "\"}]}")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(204, patched.statusCode(), patched.body());
        try {
            JsonObject doc = query("{ \"type\": [ \"" + SCHEMA_PERSON + "\" ], \"describedby\": [ \"" + SHAPE + "\" ] }");
            assertEquals(Set.of(baseUrl + "/dave"), ids(doc));
            assertEquals(Set.of(baseUrl + "/dave"),
                    ids(query("{ \"DescribedBy\": [ \"" + SHAPE + "\" ] }")), "registered names are case-insensitive");
            assertEquals(0, query("{ \"describedby\": [ \"https://shapes.example/Other\" ] }").getInt("totalItems"));
            assertEquals(0, query("{ \"https://ex.org/not-indexed\": [ \"" + SHAPE + "\" ] }").getInt("totalItems"));
            // Server-managed relations are never indexed: `up` answers nothing, though every
            // resource has one.
            assertEquals(0, query("{ \"up\": [ \"" + baseUrl + "/\" ] }").getInt("totalItems"));
        } finally {
            delete("/dave");
        }
    }

    /**
     * {@code Link: rel="type"} on a write declares the resource's type, and the type index finds it
     * (lws10-index makes this the preferred type source).
     */
    @Test
    @Order(30)
    void aDeclaredTypeIsIndexedAndSearchable() throws Exception {
        String declared = "https://schema.org/Photograph";
        HttpResponse<String> created = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/photo.bin"))
                .header("Content-Type", "application/octet-stream")
                .header("Link", "<" + declared + ">; rel=\"type\"")
                .PUT(HttpRequest.BodyPublishers.ofString("bytes")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(201, created.statusCode());

        // It reaches the resource's own metadata, alongside the structural type the server assigns.
        JsonObject linkset = Json.createReader(new StringReader(
                getRaw(baseUrl + "/photo.bin.meta").body())).readObject()
                .getJsonArray("linkset").getJsonObject(0);
        Set<String> types = new HashSet<>();
        linkset.getJsonArray("type").forEach(v -> types.add(v.asJsonObject().getString("href")));
        assertTrue(types.contains(declared), "the declared type is kept: " + types);
        assertTrue(types.contains(LWS_DATA), "the server's structural type is still there: " + types);

        // It is advertised in the resource's own Link headers, as lws10-core has every Storage
        // Resource do...
        assertTrue(getRaw(baseUrl + "/photo.bin").headers().allValues("Link")
                .contains("<" + declared + ">; rel=\"type\""), "declared type in the Link headers");
        // ...and a type search finds it, the result naming it alongside the structural type.
        JsonObject found = query(types(declared));
        assertEquals(Set.of(baseUrl + "/photo.bin"), ids(found));
        assertEquals(Json.createArrayBuilder().add("DataResource").add(declared).build(),
                found.getJsonArray("items").getJsonObject(0).getJsonArray("type"));
    }

    /**
     * A client may describe its resource and may not impersonate one. Anything in the LWS namespace
     * is refused, as are the LDP interaction models — those say what the resource is <em>to this
     * server</em>, and the server is the only party entitled to say it.
     */
    @Test
    @Order(31)
    void aClientCannotDeclareAServerManagedType() throws Exception {
        HttpResponse<String> created = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/spoof.bin"))
                .header("Content-Type", "application/octet-stream")
                .header("Link", "<https://www.w3.org/ns/lws#Storage>; rel=\"type\"")
                .header("Link", "<https://www.w3.org/ns/lws#AccessGrant>; rel=\"type\"")
                .header("Link", "<http://www.w3.org/ns/ldp#Resource>; rel=\"type\"")
                .PUT(HttpRequest.BodyPublishers.ofString("bytes")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(201, created.statusCode());

        JsonObject linkset = Json.createReader(new StringReader(
                getRaw(baseUrl + "/spoof.bin.meta").body())).readObject()
                .getJsonArray("linkset").getJsonObject(0);
        Set<String> types = new HashSet<>();
        linkset.getJsonArray("type").forEach(v -> types.add(v.asJsonObject().getString("href")));
        assertEquals(Set.of(LWS_DATA), types,
                "only the server's own structural type survives: " + types);

        assertEquals(0, query(types("https://www.w3.org/ns/lws#Storage")).getInt("totalItems"));
    }

    /**
     * The interaction models keep their existing meaning: {@code Link: rel="type"} naming one is the
     * client saying what kind of resource to <em>create</em>, and a container hint on a slash-less
     * name is still the contradiction M13 refuses.
     */
    @Test
    @Order(32)
    void theInteractionModelIsStillAnInteractionModel() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/notacontainer"))
                .header("Content-Type", "application/octet-stream")
                .header("Link", "<" + LWS_CONTAINER + ">; rel=\"type\"")
                .PUT(HttpRequest.BodyPublishers.ofString("bytes")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(400, r.statusCode(), "a container IRI must end in '/' (finding M13)");
    }

    /** OPTIONS advertises the method in Allow and the filter format in Accept-Query (RFC 10008). */
    @Test
    void optionsAdvertisesQueryAndItsFormat() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + SEARCH))
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(204, r.statusCode());
        assertTrue(r.headers().firstValue("Allow").orElse("").contains("QUERY"), r.headers().toString());
        assertEquals("application/lws-query+json", r.headers().firstValue("Accept-Query").orElse(""));
    }

    @Test
    void theQueryMustSayWhatFormatItIs() throws Exception {
        HttpResponse<String> missing = http.send(HttpRequest.newBuilder(URI.create(baseUrl + SEARCH))
                .method("QUERY", HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(400, missing.statusCode(), "RFC 10008 requires a Content-Type");

        HttpResponse<String> unsupported = rawQuery("application/sparql-query", "SELECT * WHERE { ?s ?p ?o }", null);
        assertEquals(415, unsupported.statusCode());
        assertEquals("application/lws-query+json", unsupported.headers().firstValue("Accept-Query").orElse(""),
                "a 415 lists the formats this server does accept");
    }

    @Test
    void malformedFiltersAreRejected() throws Exception {
        assertEquals(400, queryStatus("{ \"type\": \"not-an-array\" }"));
        assertEquals(400, queryStatus("{ \"type\": [ 42 ] }"));
        assertEquals(400, queryStatus("{ \"type\": [ [ ] ] }"), "an empty group is refused, not ignored");
        assertEquals(400, queryStatus("[ \"not an object\" ]"));
        assertEquals(400, queryStatus("not json"));
    }

    @Test
    void invalidIriValueIsRejected() throws Exception {
        assertEquals(400, queryStatus("{ \"type\": [ \"not a uri\" ] }"));
        assertEquals(400, queryStatus("{ \"type\": [ \"relative/uri\" ] }"));
        assertEquals(400, queryStatus("{ \"describedby\": [ \"relative\" ] }"), "relation targets too");
        assertEquals(200, queryStatus("{ \"type\": [ \"https://ex.org/t#frag\" ] }"), "a fragment is fine");
    }

    /** A filter over the server's complexity bound is 422 — understood, not processed, never narrowed. */
    @Test
    void anOverComplexFilterIsUnprocessable() throws Exception {
        StringBuilder groups = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            groups.append(i == 0 ? "" : ",").append("\"https://ex.org/t").append(i).append('"');
        }
        assertEquals(422, queryStatus("{ \"type\": [ " + groups + " ] }"));
    }

    @Test
    void anAcceptThatExcludesJsonIsNotAcceptable() throws Exception {
        assertEquals(406, rawQuery("application/lws-query+json", types(SCHEMA_PERSON), "text/turtle").statusCode());
        HttpResponse<String> ld = rawQuery("application/lws-query+json", types(SCHEMA_PERSON), "application/ld+json");
        assertEquals(200, ld.statusCode());
        assertTrue(ld.headers().firstValue("Content-Type").orElse("").startsWith("application/ld+json"));
        assertTrue(ld.headers().allValues("Vary").toString().contains("Accept"));
    }

    /** Page links are opaque and dereferenced with GET; a stale one is 404. */
    @Test
    void pageLinksDereferenceAndStaleOnesAreNotFound() throws Exception {
        HttpResponse<String> r = rawQuery("application/lws-query+json", types(SCHEMA_PERSON), null);
        String first = r.headers().allValues("Link").stream().filter(l -> l.endsWith("rel=\"first\""))
                .findFirst().orElseThrow();
        String url = first.substring(1, first.indexOf('>'));
        JsonObject again = getLws(url);
        assertEquals(Set.of(baseUrl + "/alice", baseUrl + "/bob"), ids(again));
        assertEquals(404, status(url.replace("page=1", "page=2")), "past the last page");
        assertEquals(404, status(baseUrl + SEARCH + "?q=bm90LWEtZmlsdGVy&page=1"), "an unrecognized reference");
        assertEquals(404, queryStatusAt(SEARCH + "?page=2", types(SCHEMA_PERSON)));
    }

    @Test
    void unsupportedMethodIsRejected() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + SEARCH))
                .PUT(HttpRequest.BodyPublishers.ofString("x")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(405, r.statusCode());
        assertTrue(r.headers().firstValue("Allow").orElse("").contains("QUERY"));
        HttpResponse<String> get = http.send(HttpRequest.newBuilder(URI.create(baseUrl + SEARCH)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(405, get.statusCode(), "the search itself is a QUERY, not a GET");
    }

    @Test
    void responsesAreMarkedPrivate() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + INDEX)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(r.headers().firstValue("Cache-Control").orElse("").contains("no-store"));
        assertFalse(r.headers().allValues("Link").isEmpty(), "pagination Link headers should be present");
        HttpResponse<String> q = rawQuery("application/lws-query+json", "{}", null);
        assertTrue(q.headers().firstValue("Cache-Control").orElse("").contains("private"));
    }

    // ----- helpers -----

    private static void put(String path, String turtle) throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", "text/turtle")
                .PUT(HttpRequest.BodyPublishers.ofString(turtle)).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(201, r.statusCode(), "PUT " + path + " -> " + r.statusCode() + " " + r.body());
    }

    private static void delete(String path) throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
                .DELETE().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(204, r.statusCode(), "DELETE " + path + " -> " + r.statusCode() + " " + r.body());
    }

    /** A plain GET, whatever the media type; used to read a linkset document. */
    private static HttpResponse<String> getRaw(String url) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static JsonObject getLws(String url) {
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, r.statusCode(), url + " -> " + r.statusCode() + " " + r.body());
            assertTrue(r.headers().firstValue("Content-Type").orElse("").startsWith("application/lws+json"),
                    "Content-Type was " + r.headers().firstValue("Content-Type"));
            return Json.createReader(new StringReader(r.body())).readObject();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** A filter document constraining {@code type} to the given IRIs (each its own AND group). */
    private static String types(String... iris) {
        StringBuilder sb = new StringBuilder("{ \"type\": [ ");
        for (int i = 0; i < iris.length; i++) {
            sb.append(i == 0 ? "" : ", ").append('"').append(iris[i]).append('"');
        }
        return sb.append(" ] }").toString();
    }

    /** A type search: an HTTP QUERY (RFC 10008) with an application/lws-query+json filter. */
    private static JsonObject query(String filter) throws Exception {
        HttpResponse<String> r = rawQuery("application/lws-query+json", filter, null);
        assertEquals(200, r.statusCode(), filter + " -> " + r.statusCode() + " " + r.body());
        assertTrue(r.headers().firstValue("Content-Type").orElse("").startsWith("application/lws+json"));
        return Json.createReader(new StringReader(r.body())).readObject();
    }

    private static HttpResponse<String> rawQuery(String contentType, String body, String accept) throws Exception {
        return rawQueryAt(SEARCH, contentType, body, accept);
    }

    private static HttpResponse<String> rawQueryAt(String path, String contentType, String body, String accept)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", contentType)
                .method("QUERY", HttpRequest.BodyPublishers.ofString(body));
        if (accept != null) {
            b.header("Accept", accept);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static int queryStatus(String body) throws Exception {
        return rawQuery("application/lws-query+json", body, null).statusCode();
    }

    private static int queryStatusAt(String path, String body) throws Exception {
        return rawQueryAt(path, "application/lws-query+json", body, null).statusCode();
    }

    private static int status(String url) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString()).statusCode();
    }

    private static Set<String> ids(JsonObject doc) {
        Set<String> out = new HashSet<>();
        for (JsonValue item : doc.getJsonArray("items")) {
            out.add(item.asJsonObject().getString("id"));
        }
        return out;
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
