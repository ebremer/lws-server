package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
import org.junit.jupiter.api.Test;

/**
 * HTTP integration tests for the Type Index and Type Search services (lws10-searchindex), driving a
 * live server in open mode: service discovery, the type index, GET/POST type search (single, OR, AND,
 * container and relation filters, GET/POST equivalence), and the specified error responses.
 *
 * @author Erich Bremer
 */
class SearchIndexTest {

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
        p.setProperty("lws.data-dir", Files.createTempDirectory("lws-search").toString());
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
        // Per the vocabulary, the service objects MUST hang off the lws:Storage node, each carrying
        // its rdf:type and its serviceEndpoint.
        assertTrue(serviceAdvertised(m, "TypeIndexService", baseUrl + INDEX), r.body());
        assertTrue(serviceAdvertised(m, "TypeSearchService", baseUrl + SEARCH), r.body());
    }

    private static boolean serviceAdvertised(Model model, String serviceType, String endpointIri) {
        String ask = ("""
                PREFIX lws: <https://www.w3.org/ns/lws#>
                ASK {
                  ?storage a lws:Storage ; lws:service [ a lws:%s ; lws:serviceEndpoint ?endpoint ] .
                  FILTER( str(?endpoint) = "%s" )
                }""").formatted(serviceType, endpointIri);
        try (QueryExecution qe = QueryExecutionFactory.create(QueryFactory.create(ask), model)) {
            return qe.execAsk();
        }
    }

    @Test
    void typeIndexListsDistinctVisibleTypes() {
        JsonObject doc = getLws(baseUrl + INDEX);
        assertEquals("TypeIndex", doc.getString("type"));
        Set<String> types = ids(doc);
        assertEquals(Set.of(LWS_CONTAINER, LWS_DATA, SCHEMA_PERSON, SCHEMA_EVENT, FOAF_PERSON), types);
        assertEquals(types.size(), doc.getInt("totalItems"));
    }

    @Test
    void derivedIndexReflectsCreateAndDelete() throws Exception {
        String type = "https://ex.org/Ephemeral";
        // A resource created while the derived index is in use must become searchable...
        put("/ephemeral", "<> a <" + type + "> .");
        assertTrue(ids(getLws(baseUrl + SEARCH + "?type=" + enc(type))).contains(baseUrl + "/ephemeral"),
                "a newly created resource must be searchable");
        // ...and deleting it must remove it from the index (incremental maintenance).
        delete("/ephemeral");
        assertEquals(0, getLws(baseUrl + SEARCH + "?type=" + enc(type)).getInt("totalItems"),
                "a deleted resource must leave the index");
    }

    @Test
    void typeIndexRejectsQueryWithIllegalPage() throws Exception {
        assertEquals(400, status(baseUrl + INDEX + "?page=0"));
        assertEquals(400, status(baseUrl + INDEX + "?page=abc"));
    }

    @Test
    void searchSingleType() {
        JsonObject doc = getLws(baseUrl + SEARCH + "?type=" + enc(SCHEMA_PERSON));
        assertEquals("ContainerPage", doc.getString("type"));
        assertEquals(Set.of(baseUrl + "/alice", baseUrl + "/bob"), ids(doc));
    }

    @Test
    void searchOrWithinGroup() {
        JsonObject doc = getLws(baseUrl + SEARCH + "?type=" + enc(SCHEMA_PERSON) + "," + enc(FOAF_PERSON));
        assertEquals(Set.of(baseUrl + "/alice", baseUrl + "/bob", baseUrl + "/carol"), ids(doc));
    }

    @Test
    void searchAndAcrossGroups() {
        JsonObject doc = getLws(baseUrl + SEARCH + "?type=" + enc(SCHEMA_PERSON) + "&type=" + enc(LWS_DATA));
        assertEquals(Set.of(baseUrl + "/alice", baseUrl + "/bob"), ids(doc));
    }

    @Test
    void searchByNativeContainerType() {
        JsonObject doc = getLws(baseUrl + SEARCH + "?type=" + enc(LWS_CONTAINER));
        assertEquals(Set.of(baseUrl + "/"), ids(doc));
    }

    @Test
    void getAndPostFormsAreEquivalent() throws Exception {
        Set<String> get = ids(getLws(baseUrl + SEARCH + "?type=" + enc(SCHEMA_PERSON) + "," + enc(FOAF_PERSON)));
        // POST: a single OR-group nested array.
        JsonObject post = postLws(baseUrl + SEARCH,
                "{ \"type\": [ [ \"" + SCHEMA_PERSON + "\", \"" + FOAF_PERSON + "\" ] ] }");
        assertEquals(get, ids(post));

        // POST AND: two string elements are conjoined, matching the repeated-parameter GET form.
        Set<String> getAnd = ids(getLws(baseUrl + SEARCH + "?type=" + enc(SCHEMA_PERSON) + "&type=" + enc(LWS_DATA)));
        JsonObject postAnd = postLws(baseUrl + SEARCH,
                "{ \"type\": [ \"" + SCHEMA_PERSON + "\", \"" + LWS_DATA + "\" ] }");
        assertEquals(getAnd, ids(postAnd));
    }

    @Test
    void searchByDescriptiveRelation() {
        JsonObject doc = getLws(baseUrl + SEARCH + "?type=" + enc(SCHEMA_PERSON) + "&" + enc(SHAPE_PRED) + "=" + enc(SHAPE));
        assertEquals(Set.of(baseUrl + "/alice"), ids(doc));
    }

    @Test
    void nonIndexedRelationYieldsNoResultsNotAnError() {
        // "describedby" is a bare token, not an absolute-URI predicate: the server does not index it,
        // so the conjunction yields zero matches rather than an error.
        JsonObject doc = getLws(baseUrl + SEARCH + "?type=" + enc(SCHEMA_PERSON) + "&describedby=" + enc(SHAPE));
        assertEquals(0, doc.getInt("totalItems"));
        assertTrue(ids(doc).isEmpty());
    }

    @Test
    void postWrongMediaTypeIsRejected() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + SEARCH))
                .header("Content-Type", "text/plain")
                .POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(415, r.statusCode());
    }

    @Test
    void postMalformedFilterIsRejected() throws Exception {
        assertEquals(400, postStatus(baseUrl + SEARCH, "{ \"type\": \"not-an-array\" }"));
        assertEquals(400, postStatus(baseUrl + SEARCH, "{ \"type\": [ 42 ] }"));
        assertEquals(400, postStatus(baseUrl + SEARCH, "not json"));
    }

    @Test
    void invalidUriValueIsRejected() throws Exception {
        assertEquals(400, status(baseUrl + SEARCH + "?type=" + enc("not a uri")));
        assertEquals(400, postStatus(baseUrl + SEARCH, "{ \"type\": [ \"relative/uri\" ] }"));
    }

    @Test
    void pageBeyondLastIsNotFound() throws Exception {
        assertEquals(404, status(baseUrl + SEARCH + "?type=" + enc(SCHEMA_PERSON) + "&page=2"));
    }

    @Test
    void unsupportedMethodIsRejected() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + SEARCH))
                .PUT(HttpRequest.BodyPublishers.ofString("x")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(405, r.statusCode());
        assertTrue(r.headers().firstValue("Allow").orElse("").contains("POST"));
    }

    @Test
    void responsesAreMarkedPrivate() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + INDEX)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(r.headers().firstValue("Cache-Control").orElse("").contains("no-store"));
        assertFalse(r.headers().allValues("Link").isEmpty(), "pagination Link headers should be present");
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

    private static JsonObject postLws(String url, String body) throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/lws+json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode(), url + " -> " + r.statusCode() + " " + r.body());
        return Json.createReader(new StringReader(r.body())).readObject();
    }

    private static int status(String url) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString()).statusCode();
    }

    private static int postStatus(String url, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/lws+json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString()).statusCode();
    }

    private static Set<String> ids(JsonObject doc) {
        Set<String> out = new HashSet<>();
        for (JsonValue item : doc.getJsonArray("items")) {
            out.add(item.asJsonObject().getString("id"));
        }
        return out;
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
