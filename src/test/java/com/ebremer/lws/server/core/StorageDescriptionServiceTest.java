package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
 * Tests the storage description: a controlled identifier document (lws10-core, Storage Description
 * Resource) with the mandatory {@code StorageRoot} service, the storage's signing keys as
 * verification methods, its capabilities, and the embedded SPARQL endpoint (as a W3C SPARQL Service
 * Description service) when, and only when, it is enabled.
 *
 * @author Erich Bremer
 */
class StorageDescriptionServiceTest {

    private static final String SD_SERVICE = "http://www.w3.org/ns/sparql-service-description#Service";

    @Test
    void advertisesSparqlEndpointWhenEnabled() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://storage.example");
        // An owner, because this class asserts nothing about authorization and the
        // development posture now has to be asked for explicitly.
        p.setProperty("lws.owners", "https://owner.example/profile#me");
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

        // PatchSupport maps a target format to its accepted PATCH formats, keyed `format` as in
        // lws10-core's own example.
        JsonObject patch = capabilityByType(caps, "PatchSupport");
        assertNotNull(patch, "PatchSupport capability advertised");
        assertTrue(stringsOf(patch.getJsonObject("format").getJsonArray("text/turtle"))
                .contains("application/sparql-update"));

        // ContentNegotiation, one per source format: JSON-LD in, Turtle among the targets.
        JsonObject fromJsonLd = null;
        for (JsonValue v : caps) {
            JsonObject c = v.asJsonObject();
            if (c.getString("type", "").contains("ContentNegotiation")
                    && "application/ld+json".equals(c.getString("source", null))) {
                fromJsonLd = c;
            }
        }
        assertNotNull(fromJsonLd, "a ContentNegotiation capability for application/ld+json: " + caps);
        assertTrue(stringsOf(fromJsonLd.getJsonArray("target")).contains("text/turtle"));
        assertFalse(stringsOf(fromJsonLd.getJsonArray("target")).contains("application/ld+json"),
                "a format is not its own negotiation target");
    }

    @Test
    void isAControlledIdentifierDocumentForTheStorage() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://storage.example");
        JsonObject doc = describe(p);

        // @context: an array starting with the CID and LWS contexts, in that order.
        JsonArray context = doc.getJsonArray("@context");
        assertEquals("https://www.w3.org/ns/cid/v1", context.getString(0));
        assertEquals("https://www.w3.org/ns/lws/v1", context.getString(1));
        // id: the canonical storage URI, which is also the document's own URL.
        assertEquals("http://storage.example/", doc.getString("id"));
        assertEquals("Storage", doc.getString("type"));

        // The mandatory StorageRoot service, naming the root container.
        JsonObject root = serviceByType(doc, "StorageRoot");
        assertNotNull(root, "StorageRoot service: " + doc);
        assertEquals("http://storage.example/", root.getString("serviceEndpoint"));
        // The notification service with its subscription types.
        JsonObject notifications = serviceByType(doc, "NotificationService");
        assertEquals("WebhookSubscription", notifications.getJsonArray("subscriptionType").getString(0));
        // Nothing the core no longer defines.
        assertNull(serviceByType(doc, "StorageDescription"));
        assertFalse(doc.containsKey("storageDescription"));
    }

    @Test
    void publishesSigningKeysAsAuthenticationVerificationMethods() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://storage.example");
        p.putIfAbsent("lws.owners", "https://owner.example/profile#me");
        JsonObject jwk = Json.createObjectBuilder().add("kty", "OKP").add("crv", "Ed25519")
                .add("x", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo").add("kid", "k1").build();
        StorageDescriptionService service = new StorageDescriptionService(LwsConfiguration.of(p),
                java.util.List.of(new StorageDescriptionService.VerificationKey("k1", jwk)));
        JsonObject doc = Json.createReader(new StringReader(service.buildJson())).readObject();

        JsonObject method = doc.getJsonArray("verificationMethod").getJsonObject(0);
        assertEquals("http://storage.example/#k1", method.getString("id"));
        assertEquals("JsonWebKey", method.getString("type"));
        assertEquals("http://storage.example/", method.getString("controller"));
        assertEquals(jwk, method.getJsonObject("publicKeyJwk"));
        // Referenced from `authentication`, as the webhook suite requires of a signing key.
        assertEquals("http://storage.example/#k1", doc.getJsonArray("authentication").getString(0));
        assertEquals("http://storage.example/#k1", service.verificationMethodId("k1"));
    }

    @Test
    void advertisesCurrentSpecificationsAndNotTheDiscontinuedDidKeySuite() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://storage.example");
        java.util.List<String> types = new StorageDescriptionService(withOwner(p)).capabilityTypes();
        assertTrue(types.contains("https://w3c.github.io/lws-protocol/lws10-index/"), types.toString());
        assertTrue(types.contains("https://w3c.github.io/lws-protocol/lws10-notifications-webhook/"), types.toString());
        assertTrue(types.contains("https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/"), types.toString());
        assertFalse(types.stream().anyMatch(t -> t.contains("ssi-did-key")),
                "the did:key suite was discontinued in favour of the SSI-CID suite: " + types);
        assertFalse(types.stream().anyMatch(t -> t.contains("searchindex")), types.toString());
    }

    @Test
    void rdfRenderingUsesTheCidTerms() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://storage.example");
        org.apache.jena.rdf.model.Model m = new StorageDescriptionService(withOwner(p)).buildModel();
        org.apache.jena.rdf.model.Resource storage = m.getResource("http://storage.example/");
        assertTrue(storage.hasProperty(org.apache.jena.vocabulary.RDF.type,
                m.getResource("https://www.w3.org/ns/lws#Storage")));
        org.apache.jena.rdf.model.Property service = m.getProperty("https://www.w3.org/ns/did#service");
        org.apache.jena.rdf.model.Property endpoint = m.getProperty("https://www.w3.org/ns/did#serviceEndpoint");
        boolean root = storage.listProperties(service).toList().stream()
                .map(st -> st.getObject().asResource())
                .anyMatch(s -> s.hasProperty(org.apache.jena.vocabulary.RDF.type,
                                m.getResource("https://www.w3.org/ns/lws#StorageRoot"))
                        && s.hasProperty(endpoint, m.getResource("http://storage.example/")));
        assertTrue(root, "the StorageRoot service, in the CID vocabulary");
    }

    private static LwsConfiguration withOwner(Properties p) {
        p.putIfAbsent("lws.owners", "https://owner.example/profile#me");
        return LwsConfiguration.of(p);
    }

    private static JsonObject serviceByType(JsonObject doc, String type) {
        for (JsonValue v : doc.getJsonArray("service")) {
            JsonObject service = v.asJsonObject();
            if (type.equals(service.getString("type", null))) {
                return service;
            }
        }
        return null;
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
        // An owner, because this class asserts nothing about authorization and the development
        // posture now has to be asked for explicitly.
        p.putIfAbsent("lws.owners", "https://owner.example/profile#me");
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
