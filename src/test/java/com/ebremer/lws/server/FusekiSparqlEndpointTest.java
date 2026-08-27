package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.io.StringReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Tests the optional embedded Fuseki SPARQL endpoint over the live TDB2 dataset: a SPARQL query
 * returns data the server has committed (the storage root's registry triples), every write path is
 * refused while the endpoint is read-only, the same write succeeds on a read-write endpoint, and
 * {@code lws.sparql.endpoint.loopback} really does keep the endpoint off the machine's other
 * addresses.
 *
 * <p><strong>Finding M45.</strong> The read-only test used to assert only {@code status >= 400},
 * which cannot tell "the endpoint refused the write" from "the URL was mistyped", and it never
 * checked that the write had failed to land — it could not have, because the {@code INSERT DATA}
 * targets the <em>default</em> graph while the only other query in this class counts triples in
 * <em>named</em> graphs. So every rejection below asserts the exact status this build produces, and
 * brackets itself with a probe that would see the triple in either place.
 *
 * <p><strong>Why these statuses, so that nobody "fixes" them back to {@code >= 400} or to a
 * {@code 403}.</strong> {@code FusekiSparqlServer} builds the server as
 * {@code FusekiServer.create().add(dataset, dsg, !readOnly)}, and Jena implements the read-only half
 * two ways at once:
 * <ul>
 *   <li>it registers <em>no</em> {@code update} endpoint at all, so {@code POST /lws/update} is a
 *       plain {@code 404}: nothing there refuses the write, there is nothing there;</li>
 *   <li>the dataset endpoint {@code POST /lws} answers {@code 400 "No operation for request: /lws"},
 *       because no operation it does have matches a SPARQL Update body;</li>
 *   <li>the Graph Store Protocol endpoint <em>is</em> registered, read-only, and refuses the write
 *       itself with {@code 405 "HTTP method not allowed: POST : Read-only"}.</li>
 * </ul>
 * No {@code 403} is sent anywhere on this path, and the {@code 404} is only meaningful next to
 * {@link #aReadWriteEndpointAcceptsTheSameUpdate}, which sends the same body to the same URL on a
 * server whose single difference is {@code lws.sparql.endpoint.read-only=false}.
 *
 * @author Erich Bremer
 */
class FusekiSparqlEndpointTest {

    /**
     * This class's data directory. Deleted on the way out where the platform allows it, and by the
     * next run's sweep where it does not — see {@link TestDirs}. It used to be a bare
     * {@code createTempDirectory} that nothing ever removed, and the leak once filled a disk.
     */
    private static final Path tempDir = TestDirs.create();

    /**
     * The read-write companion's data directory. It needs one of its own: a TDB2 lock file is per
     * directory, so two {@link LwsComponents} sharing a directory cannot both open the store.
     */
    private static final Path readWriteTempDir = TestDirs.create();

    /** The write every rejection test attempts. It targets the default graph. */
    private static final String PROBE_UPDATE = "INSERT DATA { <urn:x> <urn:p> \"v\" }";

    /** Looks for the probe triple in the default graph <em>and</em> in every named graph. */
    private static final String PROBE_ASK =
            "ASK { { <urn:x> <urn:p> \"v\" } UNION { GRAPH ?g { <urn:x> <urn:p> \"v\" } } }";

    private static LwsComponents components;
    private static int sparqlPort;
    private static LwsComponents readWriteComponents;
    private static int readWritePort;
    private static HttpClient http;

    @BeforeAll
    static void start() throws Exception {
        sparqlPort = freePort();
        components = LwsComponents.create(LwsConfiguration.of(
                sparqlProperties(tempDir, sparqlPort, true, true))); // starts Fuseki + ensures storage root

        readWritePort = freePort();
        readWriteComponents = LwsComponents.create(LwsConfiguration.of(
                sparqlProperties(readWriteTempDir, readWritePort, false, true)));

        // A connect timeout so that an unreachable address fails the loopback test in seconds
        // rather than hanging the build on a host that drops packets instead of refusing them.
        http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    @AfterAll
    static void stop() {
        if (components != null) {
            components.close();
        }
        if (readWriteComponents != null) {
            readWriteComponents.close();
        }
    }

    @Test
    void queryReturnsLiveData() throws Exception {
        String query = "SELECT (COUNT(*) AS ?n) WHERE { GRAPH ?g { ?s ?p ?o } }";
        HttpResponse<String> r = http.send(sparqlQuery("localhost", sparqlPort, query),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode(), r.body());

        JsonObject doc = Json.createReader(new StringReader(r.body())).readObject();
        int count = Integer.parseInt(doc.getJsonObject("results").getJsonArray("bindings")
                .getJsonObject(0).getJsonObject("n").getString("value"));
        assertTrue(count >= 1, "the storage root's metadata should be queryable; count=" + count);
    }

    /**
     * The two SPARQL-Update-shaped ways in: the endpoint Jena did not register, and the dataset
     * endpoint that has no operation for the body. The last assertion is the one that carries the
     * security meaning and it holds whichever 4xx arrives — the write did not land.
     */
    @Test
    void updateIsRejectedWhenReadOnlyAndTheDatasetIsUnchanged() throws Exception {
        assertFalse(probeTripleIsPresent(sparqlPort), "the probe triple must be absent to begin with");

        HttpResponse<String> update = postSparqlUpdate(sparqlPort, "/lws/update");
        assertEquals(404, update.statusCode(),
                "a read-only dataset registers no update endpoint at all: " + update.body());

        HttpResponse<String> dataset = postSparqlUpdate(sparqlPort, "/lws");
        assertEquals(400, dataset.statusCode(), dataset.body());
        assertTrue(dataset.body().contains("No operation"),
                "the dataset endpoint should report that no operation matches the request, got: "
                        + dataset.body());

        assertFalse(probeTripleIsPresent(sparqlPort), "a refused update must not have written anything");
    }

    /**
     * The Graph Store Protocol endpoint is the one that <em>is</em> registered when the dataset is
     * read-only, so it is also the one that has to refuse writes on its own. Asserting the reason in
     * the body is what separates "refused because the dataset is read-only" from "this method is
     * unsupported here" — the two share the 405.
     */
    @Test
    void graphStoreWritesAreRefusedAsReadOnly() throws Exception {
        assertFalse(probeTripleIsPresent(sparqlPort), "the probe triple must be absent to begin with");

        HttpResponse<String> post = http.send(graphStoreWrite("POST", "/lws/data"),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(405, post.statusCode(), post.body());
        assertTrue(post.body().contains("Read-only"),
                "the refusal must name the read-only dataset, got: " + post.body());

        HttpResponse<String> put = http.send(graphStoreWrite("PUT", "/lws/data?default"),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(405, put.statusCode(), put.body());
        assertTrue(put.body().contains("Read-only"),
                "the refusal must name the read-only dataset, got: " + put.body());

        assertFalse(probeTripleIsPresent(sparqlPort),
                "a refused graph-store write must not have written anything");
    }

    /**
     * The companion that anchors the URL: the same body, the same endpoint name, on a server whose
     * only difference is {@code read-only=false}. Without it, a mistyped path would satisfy
     * {@link #updateIsRejectedWhenReadOnlyAndTheDatasetIsUnchanged} just as happily.
     */
    @Test
    void aReadWriteEndpointAcceptsTheSameUpdate() throws Exception {
        assertFalse(probeTripleIsPresent(readWritePort), "the probe triple must be absent to begin with");

        HttpResponse<String> r = postSparqlUpdate(readWritePort, "/lws/update");
        // Fuseki finishes a direct application/sparql-update POST with ServletOps.successNoContent.
        assertEquals(204, r.statusCode(), "the read-write endpoint must accept the update: " + r.body());

        assertTrue(probeTripleIsPresent(readWritePort),
                "the accepted update must have landed in the default graph");
    }

    /**
     * {@code lws.sparql.endpoint.loopback=true} makes Fuseki bind its connector to localhost, which
     * is the only thing keeping an endpoint that bypasses WAC and exposes the admin, ACL and grant
     * graphs off the LAN. Skipped rather than failed where the host has no non-loopback IPv4
     * interface: a container with only {@code lo} is a legitimate build environment.
     */
    @Test
    void aLoopbackBoundEndpointIsNotReachableFromANonLoopbackAddress() throws Exception {
        InetAddress address = nonLoopbackIpv4Address().orElse(null);
        Assumptions.assumeTrue(address != null, "no non-loopback IPv4 interface on this host");

        // The control: the endpoint is answering right now, so the refusal below is about the
        // address and not about a server that has stopped.
        assertEquals(200, http.send(sparqlQuery("localhost", sparqlPort, "ASK {}"),
                HttpResponse.BodyHandlers.ofString()).statusCode(),
                "the endpoint must still be answering on loopback");

        assertThrows(IOException.class,
                () -> http.send(sparqlQuery(address.getHostAddress(), sparqlPort, "ASK {}"),
                        HttpResponse.BodyHandlers.ofString()),
                "loopback=true must keep the SPARQL endpoint off " + address.getHostAddress());
    }

    /**
     * The other half of the pair: the same request, to the same address, reaches a server built with
     * {@code loopback=false}. Without it the refusal above could just as well mean that this host
     * cannot reach its own LAN address at all.
     *
     * <p>That server is query-only and is torn down inside this method — binding a WAC-bypassing
     * endpoint to every interface is exactly what the test above says must not happen by accident,
     * so it exists for one request rather than for the life of the class.
     */
    @Test
    void anEndpointBoundToEveryInterfaceIsReachableFromThatSameAddress() throws Exception {
        InetAddress address = nonLoopbackIpv4Address().orElse(null);
        Assumptions.assumeTrue(address != null, "no non-loopback IPv4 interface on this host");

        int port = freePort();
        LwsComponents everywhere = LwsComponents.create(LwsConfiguration.of(
                sparqlProperties(TestDirs.create(), port, true, false)));
        try {
            HttpResponse<String> r = http.send(sparqlQuery(address.getHostAddress(), port, "ASK {}"),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, r.statusCode(),
                    "loopback=false must bind " + address.getHostAddress() + " too: " + r.body());
        } finally {
            everywhere.close();
        }
    }

    /**
     * Whether {@link #PROBE_UPDATE}'s triple is anywhere in the dataset on this port. The UNION is
     * the point: the insert targets the default graph, so a query that walks only named graphs —
     * as {@link #queryReturnsLiveData} does — would not notice the write at all.
     */
    private static boolean probeTripleIsPresent(int port) throws Exception {
        HttpResponse<String> r = http.send(sparqlQuery("localhost", port, PROBE_ASK),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode(), "the probe query itself must run: " + r.body());
        return Json.createReader(new StringReader(r.body())).readObject().getBoolean("boolean");
    }

    private static HttpResponse<String> postSparqlUpdate(int port, String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("Content-Type", "application/sparql-update")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(PROBE_UPDATE)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static HttpRequest graphStoreWrite(String method, String path) {
        return HttpRequest.newBuilder(URI.create("http://localhost:" + sparqlPort + path))
                .header("Content-Type", "text/turtle")
                .timeout(Duration.ofSeconds(30))
                .method(method, HttpRequest.BodyPublishers.ofString("<urn:x> <urn:p> \"v\" ."))
                .build();
    }

    private static HttpRequest sparqlQuery(String host, int port, String query) {
        return HttpRequest.newBuilder(URI.create("http://" + host + ":" + port + "/lws/sparql?query="
                + URLEncoder.encode(query, StandardCharsets.UTF_8)))
                .header("Accept", "application/sparql-results+json")
                .timeout(Duration.ofSeconds(30))
                .GET().build();
    }

    private static Properties sparqlProperties(Path dataDir, int port, boolean readOnly, boolean loopback)
            throws Exception {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://localhost:" + freePort());
        // An owner, because this class asserts nothing about authorization and the
        // development posture now has to be asked for explicitly.
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        p.setProperty("lws.data-dir", dataDir.toString());
        p.setProperty("lws.sparql.endpoint.enabled", "true");
        p.setProperty("lws.sparql.endpoint.port", Integer.toString(port));
        p.setProperty("lws.sparql.endpoint.dataset", "lws");
        p.setProperty("lws.sparql.endpoint.read-only", Boolean.toString(readOnly));
        p.setProperty("lws.sparql.endpoint.loopback", Boolean.toString(loopback));
        return p;
    }

    /** A site-local address if the host has one, otherwise any non-loopback IPv4 address. */
    private static Optional<InetAddress> nonLoopbackIpv4Address() {
        List<InetAddress> candidates;
        try {
            candidates = NetworkInterface.networkInterfaces()
                    .filter(FusekiSparqlEndpointTest::isUpAndNotLoopback)
                    .flatMap(NetworkInterface::inetAddresses)
                    .filter(a -> a instanceof Inet4Address && !a.isLoopbackAddress())
                    .toList();
        } catch (SocketException e) {
            return Optional.empty();
        }
        return candidates.stream().filter(InetAddress::isSiteLocalAddress).findFirst()
                .or(() -> candidates.stream().findFirst());
    }

    private static boolean isUpAndNotLoopback(NetworkInterface nic) {
        try {
            return nic.isUp() && !nic.isLoopback();
        } catch (SocketException e) {
            return false;
        }
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
