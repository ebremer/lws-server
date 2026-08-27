package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Properties;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * A client who may not read a resource is not told whether it is there.
 *
 * <p>Existence is resolved before authorization on every path in this server, so {@code 403} used to
 * mean "it exists and you may not have it" and {@code 404} "it is not there" — an existence oracle
 * over the whole storage, needing only a credential good enough to authenticate. Under WAC a name is
 * often the interesting part, and the {@code Allow} header made it worse by disclosing the
 * resource's <em>type</em> as well.
 *
 * <p>The rule pinned here: an <strong>authenticated</strong> principal without Read gets the same
 * answer, byte for byte apart from the target it named, whether the resource exists or not. An
 * <strong>anonymous</strong> client still gets {@code 401}, deliberately — it has to be able to
 * discover that authenticating is what it is missing.
 *
 * @author Erich Bremer
 */
class ExistenceOracleTest {

    /** See {@link TestDirs}: {@code @TempDir} cannot be used with a memory-mapped TDB2 dataset. */
    private static final Path tempDir = TestDirs.create();

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;
    private static String ownerToken;
    private static String bobToken;

    private static final String HIDDEN = "/oracle-secret";
    private static final String ABSENT = "/oracle-absent";
    private static final String JSON_HIDDEN = "/oracle-secret.json";

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        baseUrl = "http://localhost:" + port;
        DidKeyTool.Minted owner = DidKeyTool.mint(null, 3600, baseUrl);
        DidKeyTool.Minted bob = DidKeyTool.mint(null, 3600, baseUrl);
        ownerToken = owner.token();
        bobToken = bob.token();

        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        p.setProperty("lws.data-dir", tempDir.toString());
        p.setProperty("lws.owners", owner.did());
        // The subscription test needs its inbox to pass the delivery policy, or it is refused
        // before the topic gate it exists to exercise ever runs.
        p.setProperty("lws.webhook.allowed-hosts", "localhost");
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
        http = HttpClient.newHttpClient();

        assertEquals(201, send("PUT", HIDDEN, "secret", ownerToken,
                "Content-Type", "text/plain").statusCode());
        assertEquals(201, send("PUT", JSON_HIDDEN, "{\"secret\":\"correct\"}", ownerToken,
                "Content-Type", "application/json").statusCode());
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

    /** The regression: every method must answer a hidden resource exactly as it answers an absent one. */
    @Test
    void hiddenAndAbsentAreIndistinguishableToAnAuthenticatedClient() throws Exception {
        for (String method : new String[] {"GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"}) {
            HttpResponse<String> hidden = attempt(method, HIDDEN);
            HttpResponse<String> absent = attempt(method, ABSENT);
            assertEquals(absent.statusCode(), hidden.statusCode(),
                    () -> method + " discloses whether the resource exists");
            assertEquals(headerOf(absent, "Allow"), headerOf(hidden, "Allow"),
                    () -> method + " discloses the resource type through Allow");
            assertEquals(headerOf(absent, "Accept-Patch"), headerOf(hidden, "Accept-Patch"),
                    () -> method + " discloses the resource type through Accept-Patch");
            assertEquals(headerOf(absent, "Accept-Post"), headerOf(hidden, "Accept-Post"),
                    () -> method + " discloses the resource type through Accept-Post");
        }
    }

    /** ...and the problem document must not give it away either, beyond the target that was named. */
    @Test
    void theRefusalBodyDiscloseNothingBeyondTheTargetThatWasNamed() throws Exception {
        String hidden = attempt("GET", HIDDEN).body().replace(HIDDEN, "TARGET");
        String absent = attempt("GET", ABSENT).body().replace(ABSENT, "TARGET");
        assertEquals(absent, hidden, "the two problem documents differ by more than the target");
    }

    /**
     * An anonymous client still gets {@code 401} with a challenge, for both. Masking that as
     * {@code 404} would leave an unauthenticated client with no way to discover that it should
     * authenticate at all — which RFC 9110 and the whole discovery story depend on.
     */
    @Test
    void anAnonymousClientIsStillToldToAuthenticate() throws Exception {
        for (String path : new String[] {HIDDEN, ABSENT}) {
            HttpResponse<String> r = send("GET", path, null, null);
            assertEquals(401, r.statusCode(), path);
            assertTrue(r.headers().firstValue("WWW-Authenticate").isPresent(),
                    "a 401 must carry a challenge");
        }
    }

    /** A client who MAY read is told the truth: masking applies to those without Read, not to everyone. */
    @Test
    void aReaderStillSeesTheDifferenceBetweenPresentAndAbsent() throws Exception {
        assertEquals(200, send("GET", HIDDEN, null, ownerToken).statusCode());
        assertEquals(404, send("GET", ABSENT, null, ownerToken).statusCode());
        // ...and the owner's OPTIONS still describes the resource honestly.
        HttpResponse<String> options = send("OPTIONS", HIDDEN, null, ownerToken);
        assertEquals(204, options.statusCode());
        assertTrue(headerOf(options, "Allow").contains("DELETE"), headerOf(options, "Allow"));
    }

    /**
     * OPTIONS and 405 now vary by principal, and both statuses are heuristically cacheable
     * (RFC 9110 15.1), so a shared cache could otherwise serve one client's view to another.
     */
    @Test
    void perPrincipalResponsesAreNotStoredByASharedCache() throws Exception {
        HttpResponse<String> options = send("OPTIONS", HIDDEN, null, ownerToken);
        assertTrue(headerOf(options, "Cache-Control").contains("no-store"),
                () -> "OPTIONS: " + headerOf(options, "Cache-Control"));
        HttpResponse<String> bad = send("TRACE", HIDDEN, null, ownerToken);
        assertEquals(405, bad.statusCode());
        assertTrue(headerOf(bad, "Cache-Control").contains("no-store"),
                () -> "405: " + headerOf(bad, "Cache-Control"));
    }

    /**
     * The metadata and ACL surfaces, which are a total function of the resource.
     *
     * <p>{@code /x.meta} and {@code /x.acl} exist for every {@code /x}, so leaving either
     * unmasked restores the oracle for the whole storage no matter what the resource path does.
     * Both were verbatim copies of the pre-masking pattern and were missed the first time.
     */
    @Test
    void theMetadataAndAclSurfacesAreMaskedToo() throws Exception {
        for (String suffix : new String[] {".meta", ".acl"}) {
            for (String method : new String[] {"GET", "HEAD", "PUT", "DELETE"}) {
                int hidden = send(method, HIDDEN + suffix, bodyFor(method, suffix), bobToken,
                        contentTypeFor(method, suffix)).statusCode();
                int absent = send(method, ABSENT + suffix, bodyFor(method, suffix), bobToken,
                        contentTypeFor(method, suffix)).statusCode();
                assertEquals(absent, hidden,
                        () -> method + " " + suffix + " discloses whether the resource exists");
            }
            // ...and anonymously, where the disclosure needs no credential at all.
            assertEquals(send("GET", ABSENT + suffix, null, null).statusCode(),
                    send("GET", HIDDEN + suffix, null, null).statusCode(),
                    () -> "anonymous GET " + suffix + " discloses whether the resource exists");
        }
    }

    /**
     * A conditional write must not answer a precondition about a resource the caller may not read.
     *
     * <p>The pre-body precondition checks are deliberately permissive about authorization — a caller
     * with Append on the parent passes them — so {@code 428} ("this exists and needs a tag") versus
     * {@code 201} ("it does not") read off exactly what the masked {@code GET} withholds, along with
     * the entity-tag of anything that is there.
     */
    @Test
    void aPreconditionDoesNotAnswerForAResourceTheCallerMayNotRead() throws Exception {
        assertEquals(send("PUT", ABSENT, "x", bobToken, "Content-Type", "text/plain").statusCode(),
                send("PUT", HIDDEN, "x", bobToken, "Content-Type", "text/plain").statusCode(),
                "an unconditional PUT discloses existence through 428");
        assertEquals(
                send("PUT", ABSENT, "x", bobToken, "Content-Type", "text/plain",
                        "If-None-Match", "*").statusCode(),
                send("PUT", HIDDEN, "x", bobToken, "Content-Type", "text/plain",
                        "If-None-Match", "*").statusCode(),
                "If-None-Match: * discloses existence through 412");
    }

    /**
     * Applying a patch is a computation over content, so its failures are answers about content.
     *
     * <p>An RFC 6902 {@code test} operation is a value comparison: if the server reports "the patch
     * could not be applied" separately from "no such resource", a caller who may write but not read
     * can extract a document one comparison at a time. It must not be able to tell a {@code test}
     * that would have matched from one that would not.
     */
    @Test
    void applyingAPatchDiscloseNothingAboutADocumentTheCallerMayNotRead() throws Exception {
        String right = "[{\"op\":\"test\",\"path\":\"/secret\",\"value\":\"correct\"}]";
        String wrong = "[{\"op\":\"test\",\"path\":\"/secret\",\"value\":\"guess\"}]";
        String missing = "[{\"op\":\"remove\",\"path\":\"/not-there\"}]";
        int a = patch(JSON_HIDDEN, right);
        int b = patch(JSON_HIDDEN, wrong);
        int c = patch(JSON_HIDDEN, missing);
        int d = patch(ABSENT, right);
        assertEquals(a, b, "a failing `test` is distinguishable from a passing one");
        assertEquals(a, c, "an unresolvable pointer is distinguishable from a resolvable one");
        assertEquals(a, d, "a hidden document is distinguishable from an absent one");
    }

    private static int patch(String path, String body) throws Exception {
        return send("PATCH", path, body, bobToken,
                "Content-Type", "application/json-patch+json", "If-Match", "\"nonexistent\"")
                .statusCode();
    }

    private static String bodyFor(String method, String suffix) {
        if (!method.equals("PUT")) {
            return null;
        }
        return suffix.equals(".acl") ? "<#a> <http://www.w3.org/ns/auth/acl#mode> <#x> ."
                : "{\"linkset\":[{\"anchor\":\"x\"}]}";
    }

    private static String[] contentTypeFor(String method, String suffix) {
        if (!method.equals("PUT")) {
            return new String[0];
        }
        return new String[] {"Content-Type",
            suffix.equals(".acl") ? "text/turtle" : "application/linkset+json"};
    }

    /** Subscribing is the sharper oracle — create-versus-refused — and is closed the same way. */
    @Test
    void subscribingDoesNotDiscloseWhetherTheTopicExists() throws Exception {
        int hidden = subscribeTo(baseUrl + HIDDEN);
        int absent = subscribeTo(baseUrl + ABSENT);
        assertEquals(absent, hidden,
                "subscribing to a hidden topic must answer as it does for an absent one");
        assertFalse(hidden == 201, "neither subscription should have been created");
    }

    private static int subscribeTo(String topic) throws Exception {
        String body = "{\"type\":\"WebhookSubscription\",\"topic\":\"" + topic
                + "\",\"inbox\":\"http://localhost:1/inbox\"}";
        return send("POST", "/.lws/subscriptions", body, bobToken,
                "Content-Type", "application/lws+json").statusCode();
    }

    /** Bob has no access at all, so every one of these is a refusal. */
    private static HttpResponse<String> attempt(String method, String path) throws Exception {
        return switch (method) {
            case "PUT" -> send("PUT", path, "x", bobToken, "Content-Type", "text/plain",
                    "If-Match", "\"nonexistent\"");
            case "PATCH" -> send("PATCH", path, "{}", bobToken,
                    "Content-Type", "application/merge-patch+json", "If-Match", "\"nonexistent\"");
            default -> send(method, path, null, bobToken);
        };
    }

    private static String headerOf(HttpResponse<String> r, String name) {
        return r.headers().firstValue(name).orElse("");
    }

    private static HttpResponse<String> send(String method, String path, String body, String token,
            String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path));
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        for (int i = 0; i + 1 < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        b.method(method, body == null
                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
