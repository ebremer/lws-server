package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Properties;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Tests the optional embedded Fuseki SPARQL endpoint over the live TDB2 dataset: a SPARQL query
 * returns data the server has committed (the storage root's registry triples), and — being
 * read-only by default — a SPARQL Update is refused.
 *
 * @author Erich Bremer
 */
class FusekiSparqlEndpointTest {

    private static LwsComponents components;
    private static int sparqlPort;
    private static HttpClient http;

    @BeforeAll
    static void start() throws Exception {
        sparqlPort = freePort();
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://localhost:" + freePort());
        p.setProperty("lws.data-dir", Files.createTempDirectory("lws-fuseki").toString());
        p.setProperty("lws.sparql.endpoint.enabled", "true");
        p.setProperty("lws.sparql.endpoint.port", Integer.toString(sparqlPort));
        p.setProperty("lws.sparql.endpoint.dataset", "lws");
        p.setProperty("lws.sparql.endpoint.read-only", "true");
        p.setProperty("lws.sparql.endpoint.loopback", "true");
        components = LwsComponents.create(LwsConfiguration.of(p)); // starts Fuseki + ensures storage root
        http = HttpClient.newHttpClient();
    }

    @AfterAll
    static void stop() {
        if (components != null) {
            components.close();
        }
    }

    @Test
    void queryReturnsLiveData() throws Exception {
        String query = "SELECT (COUNT(*) AS ?n) WHERE { GRAPH ?g { ?s ?p ?o } }";
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(
                "http://localhost:" + sparqlPort + "/lws/sparql?query="
                        + URLEncoder.encode(query, StandardCharsets.UTF_8)))
                .header("Accept", "application/sparql-results+json").GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode(), r.body());

        JsonObject doc = Json.createReader(new StringReader(r.body())).readObject();
        int count = Integer.parseInt(doc.getJsonObject("results").getJsonArray("bindings")
                .getJsonObject(0).getJsonObject("n").getString("value"));
        assertTrue(count >= 1, "the storage root's metadata should be queryable; count=" + count);
    }

    @Test
    void updateIsRejectedWhenReadOnly() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(
                "http://localhost:" + sparqlPort + "/lws/update"))
                .header("Content-Type", "application/sparql-update")
                .POST(HttpRequest.BodyPublishers.ofString("INSERT DATA { <urn:x> <urn:p> \"v\" }")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(r.statusCode() >= 400, "read-only endpoint must not accept updates, got " + r.statusCode());
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
