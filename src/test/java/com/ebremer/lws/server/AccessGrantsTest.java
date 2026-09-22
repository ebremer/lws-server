package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * Integration tests for Access Requests & Grants (lws10-core/lws-access-requests): a storage
 * controller issues a grant that lets another agent read a resource it otherwise cannot, scoped to
 * the granted action, and revoking the grant withdraws the access; plus the request lifecycle,
 * controller-only grant issuance, public grants, discovery advertisement, and error cases.
 *
 * <p>It also pins finding M41 — the {@code dateTime} and {@code client} constraints and the
 * container-prefix branch of a policy's {@code target}, all reachable over HTTP with nothing
 * exercising them. Those three decide, respectively, when a grant stops working, which application
 * may use it, and how far it reaches; each fails closed, and a fail-closed branch that no test
 * enters is one that can be simplified away without anything going red.
 *
 * @author Erich Bremer
 */
class AccessGrantsTest {

    /**
     * This class's data directory. Deleted on the way out where the platform allows it, and by the
     * next run's sweep where it does not — see {@link TestDirs}. It used to be a bare
     * {@code createTempDirectory} that nothing ever removed, and the leak once filled a disk.
     */
    private static final Path tempDir = TestDirs.create();

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;
    private static String ownerToken;
    private static String bobToken;
    private static String bobDid;

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        baseUrl = "http://localhost:" + port;

        // Credentials are minted for this storage: the server requires an `aud` naming it, so a
        // token harvested here cannot be replayed against a different LWS storage.
        DidKeyTool.Minted owner = DidKeyTool.mint(null, 3600, baseUrl);
        DidKeyTool.Minted bob = DidKeyTool.mint(null, 3600, baseUrl);
        ownerToken = owner.token();
        bobToken = bob.token();
        bobDid = bob.did();

        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        p.setProperty("lws.data-dir", tempDir.toString());
        p.setProperty("lws.owners", owner.did());
        p.setProperty("lws.public-read", "false");
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

    @Test
    void grantEnablesAccessAndRevokeWithdrawsIt() throws Exception {
        assertEquals(201, owner("PUT", "/doc1", "<#it> <http://schema.org/name> \"x\" .", "text/turtle").statusCode());

        // Bob cannot read it (not the owner, not public).
        // 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, bob("GET", "/doc1", null, null).statusCode());

        // The owner grants Bob read on /doc1.
        String grant = grantJson("[\"read\"]", bobDid, baseUrl + "/doc1");
        HttpResponse<String> created = owner("POST", "/.lws/access-grants", grant, "application/lws+json");
        assertEquals(201, created.statusCode());
        String grantId = created.headers().firstValue("Location").orElseThrow();

        // Now Bob can read it...
        assertEquals(200, bob("GET", "/doc1", null, null).statusCode());
        // ...but only read: writing is still denied (the grant covers "read" only).
        assertEquals(403, bob("PUT", "/doc1", "<#it> <http://schema.org/name> \"y\" .", "text/turtle",
                "If-Match", "*").statusCode());

        // Revoking the grant immediately withdraws the access.
        assertEquals(204, owner("DELETE", path(grantId), null, null).statusCode());
        // 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, bob("GET", "/doc1", null, null).statusCode());
    }

    @Test
    void publicGrantAllowsAnonymousRead() throws Exception {
        assertEquals(201, owner("PUT", "/doc2", "<#it> <http://schema.org/name> \"x\" .", "text/turtle").statusCode());
        assertEquals(401, send("GET", "/doc2", null, null).statusCode()); // anonymous: unauthenticated

        String grant = grantJson("[\"read\"]", "http://xmlns.com/foaf/0.1/Agent", baseUrl + "/doc2");
        assertEquals(201, owner("POST", "/.lws/access-grants", grant, "application/lws+json").statusCode());

        assertEquals(200, send("GET", "/doc2", null, null).statusCode()); // anonymous now permitted
    }

    @Test
    void requestLifecycle() throws Exception {
        // Anonymous may not submit a request; the 401 links to the storage, whose URI dereferences
        // to the storage description (lws10-core).
        HttpResponse<String> anon = send("POST", "/.lws/access-requests",
                requestJson("[\"read\"]", bobDid, baseUrl + "/data/"), "application/lws+json");
        assertEquals(401, anon.statusCode());
        assertTrue(anon.headers().allValues("Link").stream()
                .anyMatch(l -> l.contains("<" + baseUrl + "/>; rel=\"https://www.w3.org/ns/lws#storage\"")),
                anon.headers().allValues("Link").toString());

        // Bob submits a request, can list and retrieve his own, then cancels it.
        HttpResponse<String> created = bob("POST", "/.lws/access-requests",
                requestJson("[\"read\", \"create\"]", bobDid, baseUrl + "/data/"), "application/lws+json");
        assertEquals(201, created.statusCode());
        String id = created.headers().firstValue("Location").orElseThrow();
        assertTrue(id.startsWith(baseUrl + "/.lws/access-requests/"));

        assertEquals(200, bob("GET", path(id), null, null).statusCode());
        assertTrue(ids(parse(bob("GET", "/.lws/access-requests", null, null).body())).contains(id));

        assertEquals(204, bob("DELETE", path(id), null, null).statusCode());
        assertEquals(404, bob("GET", path(id), null, null).statusCode());
    }

    /**
     * The access profile's {@code format} operand — {@code mediaType} until the drafts of
     * 21 August 2026 replaced the Activity Streams terms — gates a grant on the target's media type.
     */
    @Test
    void formatConstraintGatesTheGrant() throws Exception {
        assertEquals(201, owner("PUT", "/photo", "PNGDATA", "image/png").statusCode());
        // 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, bob("GET", "/photo", null, null).statusCode());

        // A grant whose format constraint does not match the target does not enable access.
        String mismatch = grantWithConstraint(baseUrl + "/photo", "format", "eq", "image/jpeg");
        String mismatchId = owner("POST", "/.lws/access-grants", mismatch, "application/lws+json")
                .headers().firstValue("Location").orElseThrow();
        // 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, bob("GET", "/photo", null, null).statusCode());
        assertEquals(204, owner("DELETE", path(mismatchId), null, null).statusCode());

        // A matching format constraint enables it.
        String match = grantWithConstraint(baseUrl + "/photo", "format", "eq", "image/png");
        assertEquals(201, owner("POST", "/.lws/access-grants", match, "application/lws+json").statusCode());
        assertEquals(200, bob("GET", "/photo", null, null).statusCode());
    }

    /** A grant written with the pre-August operand name keeps the meaning it was issued with. */
    @Test
    void theFormerMediaTypeOperandStillGatesAGrant() throws Exception {
        assertEquals(201, owner("PUT", "/legacy-photo", "PNGDATA", "image/png").statusCode());
        String grant = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/legacy-photo", "mediaType", "eq", "image/png"), "application/lws+json")
                .headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/legacy-photo", null, null).statusCode());
        } finally {
            owner("DELETE", pathOf(grant), null, null);
        }
    }

    /**
     * A target's matcher {@code type} restricts what its {@code value} covers (lws10-core, Access
     * Profile): {@code Container} matches containers only, {@code DataResource} data resources only,
     * {@code StorageResource} both — and a matcher this server does not implement is refused.
     */
    @Test
    void theTargetMatcherTypeRestrictsTheGrantToItsKind() throws Exception {
        assertEquals(201, owner("PUT", "/tm/", null, null,
                "Link", "<https://www.w3.org/ns/lws#Container>; rel=\"type\"").statusCode());
        assertEquals(201, owner("PUT", "/tm/file", "<#it> <http://schema.org/name> \"x\" .", "text/turtle").statusCode());

        String containersOnly = owner("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, baseUrl + "/tm/").replace("\"StorageResource\"", "\"Container\""),
                "application/lws+json").headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/tm/", null, null).statusCode(), "the container matches");
            assertEquals(404, bob("GET", "/tm/file", null, null).statusCode(), "a data resource under it does not");
        } finally {
            owner("DELETE", pathOf(containersOnly), null, null);
        }

        String dataOnly = owner("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, baseUrl + "/tm/")
                        .replace("\"StorageResource\"", "\"https://www.w3.org/ns/lws#DataResource\""),
                "application/lws+json").headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/tm/file", null, null).statusCode(), "the data resource matches");
            assertEquals(404, bob("GET", "/tm/", null, null).statusCode(), "the container does not");
        } finally {
            owner("DELETE", pathOf(dataOnly), null, null);
        }

        assertEquals(400, owner("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, baseUrl + "/tm/").replace("\"StorageResource\"", "\"Resource\""),
                "application/lws+json").statusCode(), "an unknown matcher is refused, not stored inert");
    }

    /**
     * The endpoints are LWS containers (lws10-core): the listing is a container representation whose
     * members are data resources, each also typed as what it is and carrying its format.
     */
    @Test
    void theGrantEndpointListsAContainerOfDataResources() throws Exception {
        String grant = owner("POST", "/.lws/access-grants", grantJson("[\"read\"]", bobDid, baseUrl + "/doc1"),
                "application/lws+json").headers().firstValue("Location").orElseThrow();
        try {
            HttpResponse<String> r = owner("GET", "/.lws/access-grants", null, null);
            assertEquals(200, r.statusCode());
            assertTrue(r.headers().allValues("Link")
                    .contains("<" + baseUrl + "/>; rel=\"https://www.w3.org/ns/lws#storage\""));
            JsonObject doc = parse(r.body());
            assertEquals("Container", doc.getString("type"));
            assertEquals(baseUrl + "/.lws/access-grants", doc.getString("id"));
            JsonObject item = null;
            for (JsonValue v : doc.getJsonArray("items")) {
                if (v.asJsonObject().getString("id").equals(grant)) {
                    item = v.asJsonObject();
                }
            }
            assertTrue(item != null, doc.toString());
            assertEquals(Json.createArrayBuilder().add("DataResource").add("AccessGrant").build(),
                    item.getJsonArray("type"));
            assertEquals("application/lws+json", item.getString("format"));
        } finally {
            owner("DELETE", pathOf(grant), null, null);
        }
    }

    /**
     * lws10-core's privacy considerations: a grant usable only through one client is not shown to
     * its assignee through another one.
     */
    @Test
    void aClientBoundGrantIsVisibleOnlyThroughThatClient() throws Exception {
        String foreign = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/doc1", "client", "eq", "https://some-other-client.example"),
                "application/lws+json").headers().firstValue("Location").orElseThrow();
        String own = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/doc1", "client", "eq", bobDid),
                "application/lws+json").headers().firstValue("Location").orElseThrow();
        try {
            Set<String> visible = ids(parse(bob("GET", "/.lws/access-grants", null, null).body()));
            assertTrue(visible.contains(own), "the grant for Bob's own client is listed");
            assertFalse(visible.contains(foreign), "the grant for another client is not");
            assertEquals(403, bob("GET", pathOf(foreign), null, null).statusCode());
            assertEquals(200, bob("GET", pathOf(own), null, null).statusCode());
        } finally {
            owner("DELETE", pathOf(foreign), null, null);
            owner("DELETE", pathOf(own), null, null);
        }
    }

    @Test
    void purposeConstraintGatesTheGrant() throws Exception {
        assertEquals(201, owner("PUT", "/secret", "<#it> <http://schema.org/name> \"x\" .", "text/turtle").statusCode());
        // 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, bob("GET", "/secret", null, null).statusCode());

        String purpose = "https://purpose.example/research";
        assertEquals(201, owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/secret", "purpose", "eq", purpose), "application/lws+json").statusCode());

        // The grant applies only when the client declares the matching purpose (LWS-Purpose header).
        // 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, bob("GET", "/secret", null, null).statusCode());                       // none declared
        // 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, bob("GET", "/secret", null, null, "LWS-Purpose",
                "https://purpose.example/ads").statusCode());                                    // wrong purpose
        assertEquals(200, bob("GET", "/secret", null, null, "LWS-Purpose", purpose).statusCode()); // matching
    }

    @Test
    void onlyAControllerMayIssueAGrant() throws Exception {
        assertEquals(403, bob("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, baseUrl + "/doc1"), "application/lws+json").statusCode());
    }

    @Test
    void wrongMediaTypeIsRejected() throws Exception {
        assertEquals(415, owner("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, baseUrl + "/doc1"), "text/plain").statusCode());
    }

    @Test
    void discoveryAdvertisesAccessServices() throws Exception {
        JsonObject doc = parse(send("GET", "/.lws/storage-description", null, null).body());
        Set<String> serviceTypes = new HashSet<>();
        boolean conformsTo = false;
        for (JsonValue v : doc.getJsonArray("service")) {
            JsonObject s = v.asJsonObject();
            serviceTypes.add(s.getString("type"));
            if (s.getString("type").equals("AccessGrantService") && s.containsKey("conformsTo")) {
                conformsTo = s.getJsonArray("conformsTo").getString(0).equals("https://www.w3.org/ns/lws#AccessProfile");
            }
        }
        assertTrue(serviceTypes.contains("AccessRequestService"), doc.toString());
        assertTrue(serviceTypes.contains("AccessGrantService"), doc.toString());
        assertTrue(conformsTo, "AccessGrantService should advertise the access profile it conforms to");
    }

    // ----- H22: a grant carries only its issuer's authority -----

    /**
     * Finding H22, the containment half. `storage` identifies this storage, so it is compared for
     * equality; a `target.value` is a scope, so it must be inside this storage. Until this check
     * existed a document could name somebody else's storage, or a target outside this one, and be
     * accepted and fully effective.
     */
    @Test
    void aGrantMustNameThisStorageAndTargetsInsideIt() throws Exception {
        assertEquals(201, owner("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, baseUrl + "/doc1"), "application/lws+json").statusCode());

        String foreignStorage = grantJson("[\"read\"]", bobDid, baseUrl + "/doc1")
                .replace("\"storage\":\"" + baseUrl + "/\"", "\"storage\":\"https://elsewhere.example/\"");
        assertEquals(400, owner("POST", "/.lws/access-grants", foreignStorage, "application/lws+json").statusCode());

        // Inside this storage but not it: containment is not identity.
        String subStorage = grantJson("[\"read\"]", bobDid, baseUrl + "/doc1")
                .replace("\"storage\":\"" + baseUrl + "/\"", "\"storage\":\"" + baseUrl + "/sub/\"");
        assertEquals(400, owner("POST", "/.lws/access-grants", subStorage, "application/lws+json").statusCode());

        assertEquals(400, owner("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, "https://elsewhere.example/secret"),
                "application/lws+json").statusCode(), "a target outside this storage must be refused");
    }

    /** A policy with no target authorized nothing but was accepted, which is a silent no-op. */
    @Test
    void aPolicyWithoutATargetIsRefused() throws Exception {
        String noTarget = "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessGrant\"],"
                + " \"storage\":\"" + baseUrl + "/\", \"access\":[{ \"type\":[\"AccessPolicy\"],"
                + " \"action\":[\"read\"], \"assignee\":\"" + bobDid + "\" }] }";
        assertEquals(400, owner("POST", "/.lws/access-grants", noTarget, "application/lws+json").statusCode());
    }

    // ----- finding M8: "modify" and "delete" are different actions -----

    /**
     * A grant naming only the ODRL action {@code modify} authorizes editing the resource and
     * <em>not</em> removing it.
     *
     * <p>Both halves discriminate. Against the pre-fix code the DELETE returns {@code 204} — the two
     * actions were folded onto a single {@code WRITE} mode, so each implied the other — and the
     * following GET returns {@code 404} rather than the {@code 200} asserted here. The PUT half
     * carries {@code If-Match} deliberately: replacing an existing resource without one is
     * {@code 428} regardless of authorization, and a test that got {@code 428} where it expected
     * {@code 403} would have passed for the wrong reason in the mirror case below.
     */
    @Test
    void aModifyGrantDoesNotAuthorizeDelete() throws Exception {
        owner("PUT", "/m8-modify", "hello", "text/plain");
        String grant = owner("POST", "/.lws/access-grants",
                grantJson("[\"modify\"]", bobDid, baseUrl + "/m8-modify"), "application/lws+json")
                .headers().firstValue("Location").orElseThrow();
        try {
            // Read as the owner: the grant deliberately names only "modify", so Bob cannot GET it,
            // and the test is about the modify/delete distinction rather than about read.
            String etag = owner("GET", "/m8-modify", null, null).headers().firstValue("ETag").orElseThrow();
            assertEquals(204, bob("PUT", "/m8-modify", "edited", "text/plain", "If-Match", etag).statusCode(),
                    "\"modify\" authorizes replacing the content");
            // 404, not 403: the grant names "modify" but not "read", and a principal without
            // Read is not told whether the resource is there.
            assertEquals(404, bob("DELETE", "/m8-modify", null, null).statusCode(),
                    "\"modify\" must NOT authorize removing the resource");
            assertEquals(200, owner("GET", "/m8-modify", null, null).statusCode(),
                    "the resource is still there");
        } finally {
            owner("DELETE", pathOf(grant), null, null);
        }
    }

    /** The mirror: {@code delete} alone does not authorize rewriting the content. */
    @Test
    void aDeleteGrantDoesNotAuthorizeModification() throws Exception {
        owner("PUT", "/m8-delete", "hello", "text/plain");
        String grant = owner("POST", "/.lws/access-grants",
                grantJson("[\"delete\"]", bobDid, baseUrl + "/m8-delete"), "application/lws+json")
                .headers().firstValue("Location").orElseThrow();
        try {
            // A refusal specifically, not merely "not 2xx": the write is refused before the body
            // is read, so a 428 here would mean the authorization check never ran. 404 rather than
            // 403 because the grant names "delete", not "read", and a principal without Read is not
            // told whether the resource is there.
            assertEquals(404, bob("PUT", "/m8-delete", "edited", "text/plain").statusCode(),
                    "\"delete\" must NOT authorize replacing the content");
            assertEquals(204, bob("DELETE", "/m8-delete", null, null).statusCode(),
                    "\"delete\" authorizes removing the resource");
        } finally {
            owner("DELETE", pathOf(grant), null, null);
        }
    }

    /**
     * The version that matters: on a container, a {@code modify}-only grant must not authorize
     * {@code DELETE … Depth: infinity}, which is the whole subtree.
     */
    @Test
    void aModifyGrantOnAContainerDoesNotAuthorizeRecursiveDelete() throws Exception {
        owner("PUT", "/m8c/", null, null, "Link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"");
        owner("PUT", "/m8c/child", "data", "text/plain");
        String grant = owner("POST", "/.lws/access-grants",
                grantJson("[\"modify\",\"read\"]", bobDid, baseUrl + "/m8c/"), "application/lws+json")
                .headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(403, bob("DELETE", "/m8c/", null, null, "Depth", "infinity").statusCode());
            assertEquals(200, owner("GET", "/m8c/child", null, null).statusCode(),
                    "the member survived the refused recursive delete");
        } finally {
            owner("DELETE", pathOf(grant), null, null);
            owner("DELETE", "/m8c/", null, null, "Depth", "infinity");
        }
    }

    /**
     * Web Access Control has no delete permission, so {@code AclMode.DELETE} must map to
     * {@code acl:Write} there. This pins the owner-mode half of the same rule: the owner's DELETE
     * still works, which it would not if the new mode had been left unmapped in an authorizer.
     */
    @Test
    void theOwnerCanStillDelete() throws Exception {
        owner("PUT", "/m8-owner", "x", "text/plain");
        assertEquals(204, owner("DELETE", "/m8-owner", null, null).statusCode());
    }

    // ----- finding M41: when a grant expires, which client may use it, and how far it reaches -----

    /**
     * A grant whose {@code dateTime lteq} bound has passed authorizes nothing, even though the
     * record is still stored and still names Bob.
     *
     * <p>Expiry is the one thing an issuer relies on to make a grant temporary, and nothing pinned
     * it. The paired control is {@link #aGrantInsideItsValidityWindowAuthorizes}: it issues the same
     * document with the bound moved into the future and expects {@code 200}, so a regression that
     * stopped honouring grants altogether goes red there rather than green here.
     */
    @Test
    void anExpiredGrantNoLongerAuthorizes() throws Exception {
        assertEquals(201, owner("PUT", "/dt-expired", "<#it> <http://schema.org/name> \"x\" .", "text/turtle")
                .statusCode());
        // 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, bob("GET", "/dt-expired", null, null).statusCode());

        HttpResponse<String> created = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/dt-expired", "dateTime", "lteq",
                        Instant.now().minusSeconds(3600).toString()), "application/lws+json");
        assertEquals(201, created.statusCode(), created.body());
        String grant = created.headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(404, bob("GET", "/dt-expired", null, null).statusCode(),
                    "a grant whose lteq bound is in the past must be inert");
        } finally {
            owner("DELETE", pathOf(grant), null, null);
        }
    }

    /** The control for {@link #anExpiredGrantNoLongerAuthorizes}: the same grant, bound still open. */
    @Test
    void aGrantInsideItsValidityWindowAuthorizes() throws Exception {
        assertEquals(201, owner("PUT", "/dt-active", "<#it> <http://schema.org/name> \"x\" .", "text/turtle")
                .statusCode());
        // 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, bob("GET", "/dt-active", null, null).statusCode());

        HttpResponse<String> created = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/dt-active", "dateTime", "lteq",
                        Instant.now().plusSeconds(3600).toString()), "application/lws+json");
        assertEquals(201, created.statusCode(), created.body());
        String grant = created.headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/dt-active", null, null).statusCode(),
                    "a grant whose lteq bound is still in the future must authorize");
        } finally {
            owner("DELETE", pathOf(grant), null, null);
        }
    }

    /**
     * {@code gteq} is the other end of the window: a grant issued to take effect later does not
     * take effect now. The second half moves the same bound into the past and expects {@code 200},
     * so the refusal above is attributable to the bound and not to the document being unusable.
     */
    @Test
    void aGrantThatHasNotStartedYetDoesNotAuthorize() throws Exception {
        assertEquals(201, owner("PUT", "/dt-notyet", "<#it> <http://schema.org/name> \"x\" .", "text/turtle")
                .statusCode());

        HttpResponse<String> pending = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/dt-notyet", "dateTime", "gteq",
                        Instant.now().plusSeconds(3600).toString()), "application/lws+json");
        assertEquals(201, pending.statusCode(), pending.body());
        String pendingGrant = pending.headers().firstValue("Location").orElseThrow();
        try {
            // 404, not 403: an authenticated principal without Read is not told whether the
            // resource is there (lws.mask-forbidden-as-not-found).
            assertEquals(404, bob("GET", "/dt-notyet", null, null).statusCode(),
                    "a grant that starts in the future must not authorize yet");
        } finally {
            owner("DELETE", pathOf(pendingGrant), null, null);
        }

        HttpResponse<String> started = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/dt-notyet", "dateTime", "gteq",
                        Instant.now().minusSeconds(3600).toString()), "application/lws+json");
        assertEquals(201, started.statusCode(), started.body());
        String startedGrant = started.headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/dt-notyet", null, null).statusCode(),
                    "the same grant, started an hour ago, authorizes");
        } finally {
            owner("DELETE", pathOf(startedGrant), null, null);
        }
    }

    /**
     * A bound the server cannot parse must not degrade into "no bound".
     *
     * <p>Issuance validates the policy's type, action, assignee and target but never its
     * constraints, so a typo in a date reaches the evaluator intact; the evaluator has to be the
     * one that refuses. The second half issues a well-formed bound against the same resource to show
     * the refusal came from the unreadable date rather than from anything else in the document.
     */
    @Test
    void anUnparseableDateTimeBoundIsInert() throws Exception {
        assertEquals(201, owner("PUT", "/dt-garbage", "<#it> <http://schema.org/name> \"x\" .", "text/turtle")
                .statusCode());

        HttpResponse<String> garbage = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/dt-garbage", "dateTime", "lteq", "tomorrow"),
                "application/lws+json");
        assertEquals(201, garbage.statusCode(), "an unparseable bound is not rejected at issuance time");
        String garbageGrant = garbage.headers().firstValue("Location").orElseThrow();
        try {
            // 404, not 403: an authenticated principal without Read is not told whether the
            // resource is there (lws.mask-forbidden-as-not-found).
            assertEquals(404, bob("GET", "/dt-garbage", null, null).statusCode(),
                    "a bound the server cannot read must fail closed, not be ignored");
        } finally {
            owner("DELETE", pathOf(garbageGrant), null, null);
        }

        HttpResponse<String> readable = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/dt-garbage", "dateTime", "lteq",
                        Instant.now().plusSeconds(3600).toString()), "application/lws+json");
        assertEquals(201, readable.statusCode(), readable.body());
        String readableGrant = readable.headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/dt-garbage", null, null).statusCode(),
                    "the same constraint with a readable bound authorizes");
        } finally {
            owner("DELETE", pathOf(readableGrant), null, null);
        }
    }

    /**
     * An operator the server does not implement is refused rather than skipped. {@code lt} is the
     * natural thing for an issuer to write and the ODRL profile does not define it here; treating an
     * uninterpretable comparison as satisfied would turn a narrower-looking grant into a wider one.
     * The two halves differ only in the operator string.
     */
    @Test
    void anUnknownDateTimeOperatorIsInert() throws Exception {
        assertEquals(201, owner("PUT", "/dt-operator", "<#it> <http://schema.org/name> \"x\" .", "text/turtle")
                .statusCode());
        String bound = Instant.now().plusSeconds(3600).toString();

        HttpResponse<String> unknown = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/dt-operator", "dateTime", "lt", bound), "application/lws+json");
        assertEquals(201, unknown.statusCode(), "an unknown operator is not rejected at issuance time");
        String unknownGrant = unknown.headers().firstValue("Location").orElseThrow();
        try {
            // 404, not 403: an authenticated principal without Read is not told whether the
            // resource is there (lws.mask-forbidden-as-not-found).
            assertEquals(404, bob("GET", "/dt-operator", null, null).statusCode(),
                    "an operator the server cannot evaluate must fail closed");
        } finally {
            owner("DELETE", pathOf(unknownGrant), null, null);
        }

        HttpResponse<String> known = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/dt-operator", "dateTime", "lteq", bound), "application/lws+json");
        assertEquals(201, known.statusCode(), known.body());
        String knownGrant = known.headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/dt-operator", null, null).statusCode(),
                    "the same bound under an operator the server does implement authorizes");
        } finally {
            owner("DELETE", pathOf(knownGrant), null, null);
        }
    }

    /**
     * The shape an issuer actually writes: two {@code dateTime} constraints on one policy, a
     * {@code gteq} floor and an {@code lteq} ceiling.
     *
     * <p>Several constraints on one policy are a conjunction — every one of them must hold — and
     * that is what makes a window expressible at all. If the evaluator ever became a disjunction the
     * closed window below would still authorize, because its floor is satisfied.
     */
    @Test
    void aTwoSidedValidityWindowAuthorizesOnlyWhileBothBoundsHold() throws Exception {
        assertEquals(201, owner("PUT", "/dt-window", "<#it> <http://schema.org/name> \"x\" .", "text/turtle")
                .statusCode());
        String window = "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessGrant\"], \"storage\":\""
                + baseUrl + "/\", \"access\":[{ \"type\":[\"AccessPolicy\"], \"action\":[\"read\"], \"assignee\":\""
                + bobDid + "\", \"target\":{ \"type\":\"StorageResource\", \"value\":[\"" + baseUrl
                + "/dt-window\"] }, \"constraint\":["
                + "{ \"leftOperand\":\"dateTime\", \"operator\":\"gteq\", \"rightOperand\":\"%s\" },"
                + "{ \"leftOperand\":\"dateTime\", \"operator\":\"lteq\", \"rightOperand\":\"%s\" }] }] }";
        String hourAgo = Instant.now().minusSeconds(3600).toString();

        HttpResponse<String> open = owner("POST", "/.lws/access-grants",
                window.formatted(hourAgo, Instant.now().plusSeconds(3600).toString()), "application/lws+json");
        assertEquals(201, open.statusCode(), open.body());
        String openGrant = open.headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/dt-window", null, null).statusCode(),
                    "now lies between the two bounds");
        } finally {
            owner("DELETE", pathOf(openGrant), null, null);
        }

        HttpResponse<String> closed = owner("POST", "/.lws/access-grants",
                window.formatted(hourAgo, Instant.now().minusSeconds(1800).toString()), "application/lws+json");
        assertEquals(201, closed.statusCode(), closed.body());
        String closedGrant = closed.headers().firstValue("Location").orElseThrow();
        try {
            // 404, not 403: an authenticated principal without Read is not told whether the
            // resource is there (lws.mask-forbidden-as-not-found).
            assertEquals(404, bob("GET", "/dt-window", null, null).statusCode(),
                    "the window has closed, even though its floor is still satisfied");
        } finally {
            owner("DELETE", pathOf(closedGrant), null, null);
        }
    }

    /**
     * A {@code client} constraint names the application the credential was issued to — the
     * {@code client_id} claim — rather than the agent, so it is the one constraint that can tell two
     * of Bob's own applications apart. The two halves are the same grant to the same assignee for
     * the same resource, differing only in the client named.
     */
    @Test
    void aClientConstraintGatesTheGrant() throws Exception {
        assertEquals(201, owner("PUT", "/client-doc", "<#it> <http://schema.org/name> \"x\" .", "text/turtle")
                .statusCode());
        // 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, bob("GET", "/client-doc", null, null).statusCode());

        // Bob's did:key credential is self-issued, so its client_id is his own DID.
        HttpResponse<String> matching = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/client-doc", "client", "eq", bobDid), "application/lws+json");
        assertEquals(201, matching.statusCode(), matching.body());
        String matchingGrant = matching.headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/client-doc", null, null).statusCode(),
                    "the request comes from the client the grant names");
        } finally {
            owner("DELETE", pathOf(matchingGrant), null, null);
        }

        HttpResponse<String> foreign = owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/client-doc", "client", "eq", "https://some-other-client.example"),
                "application/lws+json");
        assertEquals(201, foreign.statusCode(), foreign.body());
        String foreignGrant = foreign.headers().firstValue("Location").orElseThrow();
        try {
            // 404, not 403: an authenticated principal without Read is not told whether the
            // resource is there (lws.mask-forbidden-as-not-found).
            assertEquals(404, bob("GET", "/client-doc", null, null).statusCode(),
                    "the same agent, through a client the grant does not name, is refused");
        } finally {
            owner("DELETE", pathOf(foreignGrant), null, null);
        }
    }

    /** {@code isAnyOf} is membership in the listed clients, and the list is not a prefix or a wildcard. */
    @Test
    void aClientIsAnyOfConstraintMatchesAnyListedClient() throws Exception {
        assertEquals(201, owner("PUT", "/client-list", "<#it> <http://schema.org/name> \"x\" .", "text/turtle")
                .statusCode());

        HttpResponse<String> listed = owner("POST", "/.lws/access-grants",
                grantWithConstraintList(baseUrl + "/client-list", "client", "isAnyOf",
                        "https://other.example", bobDid), "application/lws+json");
        assertEquals(201, listed.statusCode(), listed.body());
        String listedGrant = listed.headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/client-list", null, null).statusCode(),
                    "the requesting client is one of the listed values");
        } finally {
            owner("DELETE", pathOf(listedGrant), null, null);
        }

        HttpResponse<String> unlisted = owner("POST", "/.lws/access-grants",
                grantWithConstraintList(baseUrl + "/client-list", "client", "isAnyOf",
                        "https://other.example", "https://third.example"), "application/lws+json");
        assertEquals(201, unlisted.statusCode(), unlisted.body());
        String unlistedGrant = unlisted.headers().firstValue("Location").orElseThrow();
        try {
            // 404, not 403: an authenticated principal without Read is not told whether the
            // resource is there (lws.mask-forbidden-as-not-found).
            assertEquals(404, bob("GET", "/client-list", null, null).statusCode(),
                    "a list that does not contain the requesting client authorizes nobody");
        } finally {
            owner("DELETE", pathOf(unlistedGrant), null, null);
        }
    }

    /**
     * The fail-closed arm no other test reaches: an anonymous request carries no client at all, so a
     * constraint naming one cannot be satisfied — not even by a grant assigned to the public agent,
     * which would otherwise let anybody in.
     *
     * <p>The {@code 401} is the anonymous refusal; masking a forbidden read as {@code 404} applies
     * only to a principal the server has authenticated. Bob's {@code 200} through the same grant is
     * the control, and it also shows the grant itself is live rather than rejected at issuance.
     */
    @Test
    void aPublicGrantWithAClientConstraintDoesNotAuthorizeAnonymousAccess() throws Exception {
        assertEquals(201, owner("PUT", "/client-public", "<#it> <http://schema.org/name> \"x\" .", "text/turtle")
                .statusCode());
        String publicGrant = "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessGrant\"],"
                + " \"storage\":\"" + baseUrl + "/\", \"access\":[{ \"type\":[\"AccessPolicy\"],"
                + " \"action\":[\"read\"], \"assignee\":\"http://xmlns.com/foaf/0.1/Agent\","
                + " \"target\":{ \"type\":\"StorageResource\", \"value\":[\"" + baseUrl + "/client-public\"] },"
                + " \"constraint\":[{ \"leftOperand\":\"client\", \"operator\":\"eq\", \"rightOperand\":\""
                + bobDid + "\" }] }] }";

        HttpResponse<String> created = owner("POST", "/.lws/access-grants", publicGrant, "application/lws+json");
        assertEquals(201, created.statusCode(), created.body());
        String grant = created.headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(401, send("GET", "/client-public", null, null).statusCode(),
                    "a request with no credential has no client and cannot satisfy the constraint");
            assertEquals(200, bob("GET", "/client-public", null, null).statusCode(),
                    "the same public grant does authorize the client it names");
        } finally {
            owner("DELETE", pathOf(grant), null, null);
        }
    }

    /**
     * A {@code target.value} ending in {@code /} is a subtree: it covers the container and
     * everything beneath it. This is the branch that lets one grant cover a whole project folder,
     * and it is also the branch that has to be exactly right, which the two tests below check from
     * the other side.
     */
    @Test
    void aGrantOnAContainerCoversItsMembers() throws Exception {
        assertEquals(201, owner("PUT", "/pfx/", null, null,
                "Link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"").statusCode());
        assertEquals(201, owner("PUT", "/pfx/child", "data", "text/plain").statusCode());
        // 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, bob("GET", "/pfx/child", null, null).statusCode());
        assertEquals(404, bob("GET", "/pfx/", null, null).statusCode());

        HttpResponse<String> created = owner("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, baseUrl + "/pfx/"), "application/lws+json");
        assertEquals(201, created.statusCode(), created.body());
        String grant = created.headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/pfx/child", null, null).statusCode(),
                    "a member of the granted container");
            assertEquals(200, bob("GET", "/pfx/", null, null).statusCode(),
                    "and the container the grant names");
        } finally {
            owner("DELETE", pathOf(grant), null, null);
        }
    }

    /**
     * The trailing slash is the whole of the distinction between "this resource" and "this
     * subtree", so a value without one must match by equality only.
     *
     * <p>Dropping it is an easy thing for an issuer to do and an easy thing for a maintainer to
     * normalize away; either would silently widen every grant naming a container. The two halves
     * differ in that one character and nothing else.
     */
    @Test
    void aGrantWithoutATrailingSlashDoesNotCoverASubtree() throws Exception {
        assertEquals(201, owner("PUT", "/pfx2/", null, null,
                "Link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"").statusCode());
        assertEquals(201, owner("PUT", "/pfx2/child", "data", "text/plain").statusCode());

        HttpResponse<String> unslashed = owner("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, baseUrl + "/pfx2"), "application/lws+json");
        assertEquals(201, unslashed.statusCode(), unslashed.body());
        String unslashedGrant = unslashed.headers().firstValue("Location").orElseThrow();
        try {
            // 404, not 403: an authenticated principal without Read is not told whether the
            // resource is there (lws.mask-forbidden-as-not-found).
            assertEquals(404, bob("GET", "/pfx2/child", null, null).statusCode(),
                    "a target with no trailing slash names one resource, not a subtree");
        } finally {
            owner("DELETE", pathOf(unslashedGrant), null, null);
        }

        HttpResponse<String> slashed = owner("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, baseUrl + "/pfx2/"), "application/lws+json");
        assertEquals(201, slashed.statusCode(), slashed.body());
        String slashedGrant = slashed.headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/pfx2/child", null, null).statusCode(),
                    "the same target with the slash restored reaches the member");
        } finally {
            owner("DELETE", pathOf(slashedGrant), null, null);
        }
    }

    /**
     * The subtree match is over IRIs, not over spellings: {@code /pfx3-sibling} shares a textual
     * prefix with {@code /pfx3} but is not inside {@code /pfx3/}, and a grant on the container must
     * not reach it. Keeping the slash on the matched value is what makes that true, and nothing
     * pinned it.
     */
    @Test
    void aContainerGrantDoesNotLeakToASiblingWithASharedPrefix() throws Exception {
        assertEquals(201, owner("PUT", "/pfx3/", null, null,
                "Link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"").statusCode());
        assertEquals(201, owner("PUT", "/pfx3/child", "data", "text/plain").statusCode());
        assertEquals(201, owner("PUT", "/pfx3-sibling", "data", "text/plain").statusCode());

        HttpResponse<String> created = owner("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, baseUrl + "/pfx3/"), "application/lws+json");
        assertEquals(201, created.statusCode(), created.body());
        String grant = created.headers().firstValue("Location").orElseThrow();
        try {
            assertEquals(200, bob("GET", "/pfx3/child", null, null).statusCode(),
                    "inside the granted container");
            // 404, not 403: an authenticated principal without Read is not told whether the
            // resource is there (lws.mask-forbidden-as-not-found).
            assertEquals(404, bob("GET", "/pfx3-sibling", null, null).statusCode(),
                    "a sibling that merely shares the prefix is outside the grant");
        } finally {
            owner("DELETE", pathOf(grant), null, null);
        }
    }

    /** The server-relative path of an absolute IRI in this storage. */
    private static String pathOf(String iri) {
        return iri.substring(baseUrl.length());
    }

    // ----- helpers -----

    private static String grantJson(String actions, String assignee, String target) {
        return "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessGrant\"], \"storage\":\""
                + baseUrl + "/\", \"access\":[{ \"type\":[\"AccessPolicy\"], \"action\":" + actions
                + ", \"assignee\":\"" + assignee + "\", \"target\":{ \"type\":\"StorageResource\", \"value\":[\""
                + target + "\"] } }] }";
    }

    private static String grantWithConstraint(String target, String left, String op, String right) {
        return "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessGrant\"], \"storage\":\""
                + baseUrl + "/\", \"access\":[{ \"type\":[\"AccessPolicy\"], \"action\":[\"read\"], \"assignee\":\""
                + bobDid + "\", \"target\":{ \"type\":\"StorageResource\", \"value\":[\"" + target + "\"] },"
                + " \"constraint\":[{ \"leftOperand\":\"" + left + "\", \"operator\":\"" + op
                + "\", \"rightOperand\":\"" + right + "\" }] }] }";
    }

    /**
     * As {@link #grantWithConstraint}, but with an array {@code rightOperand} — the shape
     * {@code isAnyOf} is defined over, and the one the single-valued helper cannot express.
     */
    private static String grantWithConstraintList(String target, String left, String op, String... right) {
        StringBuilder values = new StringBuilder();
        for (String value : right) {
            if (values.length() > 0) {
                values.append(',');
            }
            values.append('"').append(value).append('"');
        }
        return "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessGrant\"], \"storage\":\""
                + baseUrl + "/\", \"access\":[{ \"type\":[\"AccessPolicy\"], \"action\":[\"read\"], \"assignee\":\""
                + bobDid + "\", \"target\":{ \"type\":\"StorageResource\", \"value\":[\"" + target + "\"] },"
                + " \"constraint\":[{ \"leftOperand\":\"" + left + "\", \"operator\":\"" + op
                + "\", \"rightOperand\":[" + values + "] }] }] }";
    }

    private static String requestJson(String actions, String assignee, String target) {
        return "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessRequest\"], \"storage\":\""
                + baseUrl + "/\", \"access\":[{ \"type\":[\"AccessPolicy\"], \"action\":" + actions
                + ", \"assignee\":\"" + assignee + "\", \"target\":{ \"type\":\"StorageResource\", \"value\":[\""
                + target + "\"] } }] }";
    }

    private static HttpResponse<String> owner(String method, String path, String body, String contentType,
            String... extra) throws Exception {
        return authed(method, path, body, ownerToken, contentType, extra);
    }

    private static HttpResponse<String> bob(String method, String path, String body, String contentType,
            String... extra) throws Exception {
        return authed(method, path, body, bobToken, contentType, extra);
    }

    private static HttpResponse<String> authed(String method, String path, String body, String token,
            String contentType, String... extra) throws Exception {
        String[] headers = headers(token, contentType, extra);
        return send(method, path, body, contentType == null ? null : contentType, headers);
    }

    private static String[] headers(String token, String contentType, String... extra) {
        java.util.List<String> h = new java.util.ArrayList<>();
        h.add("Authorization");
        h.add("Bearer " + token);
        for (int i = 0; i + 1 < extra.length; i += 2) {
            h.add(extra[i]);
            h.add(extra[i + 1]);
        }
        return h.toArray(new String[0]);
    }

    private static HttpResponse<String> send(String method, String path, String body, String contentType,
            String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path));
        if (contentType != null) {
            b.header("Content-Type", contentType);
        }
        for (int i = 0; i + 1 < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String path(String iri) {
        return iri.substring(baseUrl.length());
    }

    private static Set<String> ids(JsonObject doc) {
        Set<String> out = new HashSet<>();
        for (JsonValue item : doc.getJsonArray("items")) {
            out.add(item.asJsonObject().getString("id"));
        }
        return out;
    }

    private static JsonObject parse(String json) {
        return Json.createReader(new StringReader(json)).readObject();
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
