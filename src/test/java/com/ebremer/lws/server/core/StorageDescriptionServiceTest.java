package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.util.Properties;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * Tests that the storage description advertises the embedded SPARQL endpoint (as a W3C SPARQL
 * Service Description service) when, and only when, it is enabled.
 *
 * @author Erich Bremer
 */
class StorageDescriptionServiceTest {

    private static final String SD_SERVICE = "http://www.w3.org/ns/sparql-service-description#Service";

    @Test
    void advertisesSparqlEndpointWhenEnabled() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://storage.example");
        p.setProperty("lws.sparql.endpoint.enabled", "true");
        p.setProperty("lws.sparql.endpoint.public-url", "https://storage.example/sparql");
        JsonObject doc = describe(p);
        assertEquals("https://storage.example/sparql", sparqlEndpoint(doc));
    }

    @Test
    void derivesEndpointUrlFromBaseHostAndPort() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://localhost:8080");
        p.setProperty("lws.sparql.endpoint.enabled", "true");
        p.setProperty("lws.sparql.endpoint.port", "3030");
        p.setProperty("lws.sparql.endpoint.dataset", "lws");
        assertEquals("http://localhost:3030/lws/sparql", sparqlEndpoint(describe(p)));
    }

    @Test
    void noSparqlServiceWhenDisabled() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://storage.example"); // endpoint disabled by default
        assertFalse(hasSparqlService(describe(p)), "no SPARQL service should be advertised when disabled");
    }

    @Test
    void advertisesStructuredCapabilities() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://storage.example");
        JsonArray caps = describe(p).getJsonArray("capability");

        // RFC 9530 digest capability carries its supported algorithms.
        JsonObject digest = capabilityByType(caps, "rfc9530");
        assertNotNull(digest, "digest capability advertised: " + caps);
        assertTrue(stringsOf(digest.getJsonArray("algorithm")).contains("sha-256"));

        // PatchSupport maps a target media type to its accepted PATCH formats.
        JsonObject patch = capabilityByType(caps, "PatchSupport");
        assertNotNull(patch, "PatchSupport capability advertised");
        assertTrue(stringsOf(patch.getJsonObject("mediaType").getJsonArray("text/turtle"))
                .contains("application/sparql-update"));

        // ContentNegotiation lists the interchangeable RDF serialisations.
        JsonObject negotiation = capabilityByType(caps, "ContentNegotiation");
        assertNotNull(negotiation, "ContentNegotiation capability advertised");
        assertTrue(stringsOf(negotiation.getJsonArray("target")).contains("text/turtle"));
    }

    private static JsonObject capabilityByType(JsonArray caps, String typeSubstring) {
        for (JsonValue v : caps) {
            JsonObject c = v.asJsonObject();
            if (c.getString("type", "").contains(typeSubstring)) {
                return c;
            }
        }
        return null;
    }

    private static java.util.List<String> stringsOf(JsonArray array) {
        return array.stream().map(v -> ((JsonString) v).getString()).toList();
    }

    private static JsonObject describe(Properties p) {
        return Json.createReader(new StringReader(
                new StorageDescriptionService(LwsConfiguration.of(p)).buildJson())).readObject();
    }

    private static boolean hasSparqlService(JsonObject doc) {
        return sparqlEndpoint(doc) != null;
    }

    /** The serviceEndpoint of the advertised SPARQL service, or null if none. */
    private static String sparqlEndpoint(JsonObject doc) {
        for (JsonValue v : doc.getJsonArray("service")) {
            JsonObject service = v.asJsonObject();
            if (SD_SERVICE.equals(service.getString("type", null))) {
                return service.getString("serviceEndpoint", null);
            }
        }
        return null;
    }
}
