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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.riot.RDFLanguages;
import org.apache.jena.riot.RDFFormat;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.DatasetGraphFactory;
import org.apache.jena.vocabulary.DCTerms;
import org.apache.jena.vocabulary.RDF;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.rdf.RdfIO;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * The LWS profile in container content negotiation (lws10-core, LWS Profile and Content
 * Negotiation, drafts of 19 October 2026), over real HTTP.
 *
 * <p>The rule: a client asks for a container in the LWS profile with the {@code profile} parameter
 * of an RDF media type; if the server selects that media type, the response "MUST be RDF isomorphic
 * to the application/lws+json representation" of the same container state and page, and its
 * {@code Content-Type} "MUST include the same profile parameter". The check here is the one the
 * definition gives: read each response as RDF by its own {@code Content-Type}, read the lws+json
 * response of the same page as JSON-LD with the bundled LWS context, and compare with
 * {@link Model#isIsomorphicWith}. One test also states the expected triples outright, so the
 * comparison is not merely of the server with itself.
 *
 * <p>The page size is 2, so {@code /prof/} — a text file, a JSON file with a declared type, and a
 * container — is two pages, and {@code /flat/} one.
 *
 * @author Erich Bremer
 */
class ContainerProfileTest {

    private static final String LWS_PROFILE = "https://www.w3.org/ns/lws/v1";
    private static final String IN_PROFILE = "; profile=\"" + LWS_PROFILE + "\"";
    private static final String LWS = "https://www.w3.org/ns/lws#";
    private static final String CUSTOM_TYPE = "https://example.org/Custom";

    /** The RDF media types a container is offered in, and the JSON-LD one that is the document itself. */
    private static final List<String> RDF_TYPES = List.of("application/ld+json", "text/turtle",
            "application/n-triples", "application/trig", "application/n-quads", "application/rdf+xml");

    /** See {@link TestDirs}: {@code @TempDir} cannot be used with a memory-mapped TDB2 dataset. */
    private static final Path tempDir = TestDirs.create();

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;
    private static String token;

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        baseUrl = "http://localhost:" + port;
        DidKeyTool.Minted owner = DidKeyTool.mint(null, 3600, baseUrl);
        token = owner.token();
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        p.setProperty("lws.data-dir", tempDir.toString());
        p.setProperty("lws.owners", owner.did());
        p.setProperty("lws.container.page-size", "2");
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
        http = HttpClient.newHttpClient();

        String containerType = "<https://www.w3.org/ns/lws#Container>; rel=\"type\"";
        assertEquals(201, send("PUT", "/prof/", null, "Link", containerType).statusCode());
        assertEquals(201, send("PUT", "/prof/note.txt", "in the profile", "Content-Type", "text/plain")
                .statusCode());
        assertEquals(201, send("PUT", "/prof/typed.json", "{\"a\":1}", "Content-Type", "application/json",
                "Link", "<" + CUSTOM_TYPE + ">; rel=\"type\"").statusCode());
        assertEquals(201, send("PUT", "/prof/inner/", null, "Link", containerType).statusCode());
        assertEquals(201, send("PUT", "/flat/", null, "Link", containerType).statusCode());
        assertEquals(201, send("PUT", "/flat/a.txt", "a", "Content-Type", "text/plain").statusCode());
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

    /**
     * Every RDF media type, asked for in the LWS profile and without it, on every page: the RDF is
     * that of the lws+json representation of the same page, with the same pagination links, and the
     * profile is named exactly when it was asked for.
     */
    @Test
    void everyRdfRepresentationIsIsomorphicToTheLwsJsonOfTheSamePage() throws Exception {
        for (String path : List.of("/prof/", "/prof/?page=2", "/flat/")) {
            HttpResponse<byte[]> json = get(path, "application/lws+json");
            assertEquals(200, json.statusCode(), path);
            assertEquals("application/lws+json", mediaType(json));
            Model expected = rdfOf(json);
            assertTrue(expected.size() > 3, path);
            for (String type : RDF_TYPES) {
                for (boolean profile : new boolean[] {true, false}) {
                    String accept = profile ? type + IN_PROFILE : type;
                    HttpResponse<byte[]> r = get(path, accept);
                    String what = path + " as " + accept;
                    assertEquals(200, r.statusCode(), what);
                    assertEquals(type, mediaType(r), what);
                    assertEquals(profile, namesTheLwsProfile(r), what + ": " + contentType(r));
                    assertTrue(r.headers().allValues("Vary").stream().anyMatch(v -> v.contains("Accept")), what);
                    assertEquals(pageLinks(json), pageLinks(r), what + " is paginated as the JSON is");
                    Model actual = rdfOf(r);
                    assertTrue(actual.isIsomorphicWith(expected), () -> what + " is not the RDF of the lws+json:\n"
                            + RdfIO.writeString(actual, RDFFormat.NTRIPLES) + "\nexpected\n"
                            + RdfIO.writeString(expected, RDFFormat.NTRIPLES));
                }
            }
        }
    }

    /**
     * What the RDF says, stated outright: the container's type, its {@code totalItems} over the whole
     * membership and its {@code items} on this page; each data resource's type, format, size and
     * modified time; a declared type; and nothing the JSON does not say — no {@code lws:storage},
     * no modified time on the container or on a contained container, which the LWS context does not
     * define for containers.
     */
    @Test
    void theRdfSaysWhatTheJsonSaysAndNothingElse() throws Exception {
        Model page1 = rdfOf(get("/prof/", "text/turtle" + IN_PROFILE));
        Model page2 = rdfOf(get("/prof/?page=2", "text/turtle" + IN_PROFILE));
        Resource c = page1.createResource(baseUrl + "/prof/");
        Property items = page1.createProperty(LWS + "items");
        Property totalItems = page1.createProperty(LWS + "totalItems");
        for (Model page : List.of(page1, page2)) {
            assertTrue(page.contains(c, RDF.type, page.createResource(LWS + "Container")));
            assertTrue(page.contains(c, totalItems, page.createTypedLiteral("3", XSDDatatype.XSDinteger)),
                    "totalItems is the whole membership on every page");
            assertFalse(page.contains(c, page.createProperty(LWS + "storage")), "the JSON names no storage");
            assertFalse(page.contains(c, DCTerms.modified), "the JSON gives the container no modified time");
        }
        assertEquals(2, page1.listObjectsOfProperty(c, items).toList().size());
        assertEquals(1, page2.listObjectsOfProperty(c, items).toList().size());

        Model all = ModelFactory.createDefaultModel().add(page1).add(page2);
        Resource note = all.createResource(baseUrl + "/prof/note.txt");
        Resource typed = all.createResource(baseUrl + "/prof/typed.json");
        Resource inner = all.createResource(baseUrl + "/prof/inner/");
        for (Resource member : List.of(note, typed, inner)) {
            assertTrue(all.contains(c, items, member), member.getURI());
        }
        assertTrue(all.contains(note, RDF.type, all.createResource(LWS + "DataResource")));
        assertTrue(all.contains(note, DCTerms.format, "text/plain"));
        assertTrue(all.contains(note, all.createProperty("http://schema.org/size"),
                all.createTypedLiteral("14", XSDDatatype.XSDlong)));
        assertEquals(XSDDatatype.XSDdateTime.getURI(),
                all.getRequiredProperty(note, DCTerms.modified).getLiteral().getDatatypeURI());
        assertTrue(all.contains(typed, RDF.type, all.createResource(CUSTOM_TYPE)), "the declared type");
        assertTrue(all.contains(typed, DCTerms.format, "application/json"));
        assertTrue(all.contains(inner, RDF.type, all.createResource(LWS + "Container")));
        assertFalse(all.contains(inner, DCTerms.modified), "modified is a DataResource term only");
    }

    /**
     * One entity-tag per representation and page (RFC 9110 &sect;8.8.1, finding M21): each RDF
     * serialization differs from the JSON and from every other, and each page from every other. The
     * three JSON media types are one document and share a tag, as they always have; naming the
     * profile changes the {@code Content-Type}, not the bytes, so it shares the tag of the same
     * serialization without it.
     */
    @Test
    void entityTagsDifferPerRepresentationAndPage() throws Exception {
        Map<String, String> tags = new HashMap<>();
        for (String path : List.of("/prof/", "/prof/?page=2")) {
            for (String accept : List.of("application/lws+json", "text/turtle" + IN_PROFILE,
                    "application/n-triples" + IN_PROFILE, "application/trig" + IN_PROFILE,
                    "application/n-quads" + IN_PROFILE, "application/rdf+xml")) {
                tags.put(path + " " + accept, get(path, accept).headers().firstValue("ETag").orElseThrow());
            }
        }
        assertEquals(tags.size(), new HashSet<>(tags.values()).size(), "a tag is shared: " + tags);

        assertEquals(etag("/prof/", "application/lws+json"), etag("/prof/", "application/ld+json" + IN_PROFILE));
        assertEquals(etag("/prof/", "text/turtle"), etag("/prof/", "text/turtle" + IN_PROFILE));
        assertEquals(etag("/flat/", "application/n-quads"), etag("/flat/", "application/n-quads" + IN_PROFILE));
        assertTrue(etag("/flat/", "application/n-quads").endsWith(".nq\""), etag("/flat/", "application/n-quads"));
    }

    /** A {@code 304} answers only for the representation and page the client holds, and says it varies. */
    @Test
    void conditionalReadsArePerRepresentationAndPage() throws Exception {
        String accept = "text/turtle" + IN_PROFILE;
        String tag = etag("/prof/?page=2", accept);
        HttpResponse<byte[]> notModified = get("/prof/?page=2", accept, "If-None-Match", tag);
        assertEquals(304, notModified.statusCode());
        assertEquals(tag, notModified.headers().firstValue("ETag").orElse(""));
        assertTrue(notModified.headers().allValues("Vary").stream().anyMatch(v -> v.contains("Accept")));

        assertEquals(200, get("/prof/?page=2", "application/n-triples" + IN_PROFILE, "If-None-Match", tag)
                .statusCode(), "N-Triples is another representation");
        assertEquals(200, get("/prof/?page=2", "application/lws+json", "If-None-Match", tag).statusCode());
        assertEquals(200, get("/prof/", accept, "If-None-Match", tag).statusCode(), "page 1 is another page");

        String flat = etag("/flat/", accept);
        assertEquals(304, get("/flat/", accept, "If-None-Match", flat).statusCode());
    }

    /** Past the last page there is nothing, in any representation. */
    @Test
    void pastTheLastPageIsNotFoundInEveryRepresentation() throws Exception {
        for (String accept : List.of("application/lws+json", "text/turtle" + IN_PROFILE,
                "application/ld+json" + IN_PROFILE, "application/n-quads")) {
            assertEquals(404, get("/prof/?page=3", accept).statusCode(), accept);
        }
    }

    /**
     * This server produces no profile but the LWS one, so a range naming another matches nothing
     * and the container answers with lws+json, the representation it must always honour — and
     * claims no profile.
     */
    @Test
    void anotherProfileIsNeitherSelectedNorClaimed() throws Exception {
        for (String accept : List.of("text/turtle; profile=\"https://example.org/other\"",
                "application/ld+json; profile=\"https://example.org/other\"")) {
            HttpResponse<byte[]> r = get("/prof/", accept);
            assertEquals(200, r.statusCode(), accept);
            assertEquals("application/lws+json", mediaType(r), accept);
            assertFalse(contentType(r).contains("profile"), contentType(r));
        }
    }

    /**
     * The storage URI is the root container's too. The LWS profile is defined for container
     * representations, so a client that names it is asking for the container; the storage
     * description is still what a client with no preference gets.
     */
    @Test
    void theStorageUriAskedForInTheProfileIsTheRootContainer() throws Exception {
        HttpResponse<byte[]> turtle = get("/", "text/turtle" + IN_PROFILE);
        assertEquals(200, turtle.statusCode());
        assertEquals("text/turtle", mediaType(turtle));
        assertTrue(namesTheLwsProfile(turtle));
        Model root = rdfOf(turtle);
        assertTrue(root.contains(root.createResource(baseUrl + "/"), RDF.type, root.createResource(LWS + "Container")));
        assertTrue(root.isIsomorphicWith(rdfOf(get("/", "application/lws+json"))));

        HttpResponse<byte[]> ld = get("/", "application/ld+json" + IN_PROFILE);
        assertEquals("application/ld+json", mediaType(ld));
        assertTrue(namesTheLwsProfile(ld));
        assertEquals("Container", json(ld).getString("type"));

        assertEquals("application/lws+cid", mediaType(get("/", null)));
    }

    /**
     * The server-managed listings are containers too, and negotiate as one: the subscription list
     * and the access-request endpoint answer in the LWS profile with the RDF of their lws+json. A
     * subscription itself is not a container, so it never claims the profile.
     */
    @Test
    void serverManagedListingsAreNegotiatedLikeContainers() throws Exception {
        HttpResponse<byte[]> sub = send("POST", "/.lws/subscriptions", "{\"type\":\"WebhookSubscription\","
                + "\"topic\":\"" + baseUrl + "/prof/\",\"inbox\":\"https://8.8.8.8/notify\"}",
                "Content-Type", "application/lws+json");
        assertEquals(201, sub.statusCode(), new String(sub.body(), StandardCharsets.UTF_8));
        String subscription = sub.headers().firstValue("Location").orElseThrow();
        HttpResponse<byte[]> request = send("POST", "/.lws/access-requests", "{ \"@context\":\"" + LWS_PROFILE
                + "\", \"type\":[\"AccessRequest\"], \"storage\":\"" + baseUrl + "/\", \"access\":[{ \"type\":"
                + "[\"AccessPolicy\"], \"action\":[\"read\"], \"assignee\":\"did:example:alice\", \"target\":{"
                + " \"type\":\"StorageResource\", \"value\":[\"" + baseUrl + "/prof/\"] } }] }",
                "Content-Type", "application/lws+json");
        assertEquals(201, request.statusCode(), new String(request.body(), StandardCharsets.UTF_8));

        for (String path : List.of("/.lws/subscriptions", "/.lws/access-requests")) {
            HttpResponse<byte[]> json = get(path, "application/lws+json");
            assertEquals(200, json.statusCode(), path);
            assertEquals(1, json(json).getInt("totalItems"), path);
            Model expected = rdfOf(json);
            for (String type : RDF_TYPES) {
                HttpResponse<byte[]> r = get(path, type + IN_PROFILE);
                String what = path + " as " + type;
                assertEquals(200, r.statusCode(), what);
                assertEquals(type, mediaType(r), what);
                assertTrue(namesTheLwsProfile(r), what + ": " + contentType(r));
                assertTrue(r.headers().allValues("Vary").stream().anyMatch(v -> v.contains("Accept")), what);
                assertTrue(r.headers().firstValue("Cache-Control").orElse("").contains("no-store"), what);
                assertTrue(rdfOf(r).isIsomorphicWith(expected), what);
            }
            Model turtle = rdfOf(get(path, "text/turtle"));
            Resource listing = turtle.createResource(baseUrl + path);
            Resource member = turtle.listObjectsOfProperty(listing, turtle.createProperty(LWS + "items"))
                    .next().asResource();
            assertTrue(turtle.contains(member, RDF.type, turtle.createResource(LWS + "DataResource")), path);
            assertTrue(turtle.contains(member, DCTerms.format, "application/lws+json"), path);
        }
        Model subscriptions = rdfOf(get("/.lws/subscriptions", "text/turtle"));
        assertTrue(subscriptions.contains(subscriptions.createResource(subscription), RDF.type,
                subscriptions.createResource(LWS + "WebhookSubscription")), "the member's specific type");

        HttpResponse<byte[]> one = get(subscription.substring(baseUrl.length()), "application/ld+json" + IN_PROFILE);
        assertEquals(200, one.statusCode());
        assertEquals("application/lws+json", mediaType(one), "a subscription is not in the LWS profile");
        assertFalse(contentType(one).contains("profile"), contentType(one));
    }

    /**
     * A type search or type index result is "a synthetic result set, not a representation of a
     * container" (lws10-index), so it is not in the LWS profile: asked for only in the profile, the
     * index has nothing acceptable and says {@code 406}, and it never claims the profile.
     */
    @Test
    void searchResultsAreNotInTheLwsProfile() throws Exception {
        assertEquals(406, get("/.lws/type-index", "application/ld+json" + IN_PROFILE).statusCode());
        HttpResponse<byte[]> plain = get("/.lws/type-index", "application/ld+json");
        assertEquals(200, plain.statusCode());
        assertEquals("application/ld+json", mediaType(plain));
        HttpResponse<byte[]> mixed = get("/.lws/type-index", "application/ld+json" + IN_PROFILE
                + ", application/lws+json;q=0.5");
        assertEquals(200, mixed.statusCode());
        assertEquals("application/lws+json", mediaType(mixed));
        assertFalse(contentType(mixed).contains("profile"));
    }

    // ----- helpers -----

    /**
     * The RDF a response encodes, read by its own {@code Content-Type}: the JSON family as JSON-LD
     * with the bundled contexts, everything else by its RDF syntax. Named-graph data is refused,
     * because a container's representation is one graph.
     */
    private static Model rdfOf(HttpResponse<byte[]> r) {
        String type = mediaType(r);
        String base = r.uri().toString();
        if (type.equals("application/lws+json") || type.equals("application/json")
                || type.equals("application/ld+json")) {
            return RdfIO.parse(r.body(), Lang.JSONLD, base);
        }
        Lang lang = RDFLanguages.contentTypeToLang(type);
        assertTrue(lang != null, "not an RDF media type: " + type);
        DatasetGraph dsg = DatasetGraphFactory.create();
        RDFDataMgr.read(dsg, new ByteArrayInputStream(r.body()), base, lang);
        assertFalse(dsg.listGraphNodes().hasNext(), "a container's RDF is its default graph only");
        return ModelFactory.createModelForGraph(dsg.getDefaultGraph());
    }

    private static String contentType(HttpResponse<?> r) {
        return r.headers().firstValue("Content-Type").orElse("");
    }

    private static String mediaType(HttpResponse<?> r) {
        String ct = contentType(r);
        int semi = ct.indexOf(';');
        return (semi < 0 ? ct : ct.substring(0, semi)).trim().toLowerCase(java.util.Locale.ROOT);
    }

    /** Whether the Content-Type carries a profile parameter naming the LWS profile (the Touchstone pattern). */
    private static boolean namesTheLwsProfile(HttpResponse<?> r) {
        return java.util.regex.Pattern.compile(
                "(?i);\\s*profile\\s*=\\s*\"?([^\";]*\\s)?https://www\\.w3\\.org/ns/lws/v1(\\s[^\";]*)?\"?\\s*(;|$)")
                .matcher(contentType(r)).find();
    }

    private static Set<String> pageLinks(HttpResponse<?> r) {
        Set<String> out = new HashSet<>();
        for (String link : r.headers().allValues("Link")) {
            for (String rel : List.of("first", "prev", "next", "last")) {
                if (link.contains("rel=\"" + rel + "\"")) {
                    out.add(link);
                }
            }
        }
        return out;
    }

    private static JsonObject json(HttpResponse<byte[]> r) {
        return Json.createReader(new StringReader(new String(r.body(), StandardCharsets.UTF_8))).readObject();
    }

    private static String etag(String path, String accept) throws Exception {
        HttpResponse<byte[]> r = get(path, accept);
        assertEquals(200, r.statusCode(), path + " " + accept);
        return r.headers().firstValue("ETag").orElseThrow();
    }

    private static HttpResponse<byte[]> get(String path, String accept, String... headers) throws Exception {
        List<String> all = new ArrayList<>(List.of(headers));
        if (accept != null) {
            all.add("Accept");
            all.add(accept);
        }
        return send("GET", path, null, all.toArray(String[]::new));
    }

    private static HttpResponse<byte[]> send(String method, String path, String body, String... headers)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + token);
        for (int i = 0; i + 1 < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        b.method(method, body == null
                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
