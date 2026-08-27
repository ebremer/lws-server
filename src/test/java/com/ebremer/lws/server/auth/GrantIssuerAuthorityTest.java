package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.time.Clock;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import org.apache.jena.query.DatasetFactory;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.AccessService;
import com.ebremer.lws.server.core.AclMode;
import com.ebremer.lws.server.core.Authorizer;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;

/**
 * Finding H22. An access grant is invisible in {@code lws.owners} and in every ACL, it is persisted,
 * and it used to be evaluated without ever asking who issued it or whether they were still entitled
 * to. The reproduction: on the shipped defaults a self-minted {@code did:key} POSTed itself a grant
 * over the whole storage, and it survived a restart, an owner list, {@code lws.public-read=false}
 * and a switch to WAC.
 *
 * <p>A grant now carries only the authority of the agent who issued it, asked about again at every
 * evaluation rather than trusted from issuance.
 *
 * @author Erich Bremer
 */
class GrantIssuerAuthorityTest {

    private static final String BASE = "http://localhost:8080";
    private static final String CAROL = "https://carol.example/profile#me";
    private static final String BOB = "https://bob.example/profile#me";

    private final LwsPrincipal bob = new LwsPrincipal(BOB, "iss", null);

    @Test
    void aGrantStopsAuthorizingWhenItsIssuerStopsBeingAController() throws Exception {
        RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        try {
            // Carol is a controller when she issues the grant...
            List<String> controllers = new java.util.ArrayList<>(List.of(CAROL));
            AccessService access = accessService(store, controllers::contains);
            access.create(new LwsPrincipal(CAROL, "iss", null), AccessService.Kind.GRANT,
                    grant(BOB, BASE + "/doc").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            assertTrue(access.grants(bob, BASE + "/doc", AclMode.READ, java.time.Instant.now()),
                    "the grant authorizes while its issuer controls the storage");

            // ... and stops being one. No restart, no stored record to clean up.
            controllers.clear();
            assertFalse(access.grants(bob, BASE + "/doc", AclMode.READ, java.time.Instant.now()),
                    "the grant must stop authorizing on the very next request");
        } finally {
            store.close();
        }
    }

    /** A grant with no recorded issuer has nobody's authority behind it, so it has none. */
    @Test
    void aGrantWithNoRecordedIssuerAuthorizesNothing() throws Exception {
        RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        try {
            AccessService access = accessService(store, webId -> true);
            access.create(new LwsPrincipal(CAROL, "iss", null), AccessService.Kind.GRANT,
                    grant(BOB, BASE + "/doc").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            assertTrue(access.grants(bob, BASE + "/doc", AclMode.READ, java.time.Instant.now()));

            // Strip the issuer triple, as a store written by hand or by an older build might have it.
            store.writeDo(conn -> conn.update(
                    "DELETE WHERE { GRAPH <urn:x-lws:access> { ?s <urn:x-lws:accessCreator> ?o } }"));
            assertFalse(access.grants(bob, BASE + "/doc", AclMode.READ, java.time.Instant.now()),
                    "the issuer join is INNER on purpose; an OPTIONAL here would fail open");
        } finally {
            store.close();
        }
    }

    /**
     * The controller question is asked once per distinct <em>issuer</em>, not once per grant. Only
     * controllers can issue, so issuers repeat; measured on a 200-grant fixture, asking per grant
     * costs +29% under WAC and +190% in owner mode, and asking per issuer costs under 1%.
     */
    @Test
    void theIssuerCheckIsMadeOncePerIssuerNotOncePerGrant() throws Exception {
        RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        try {
            AtomicInteger asked = new AtomicInteger();
            AccessService access = accessService(store, webId -> {
                asked.incrementAndGet();
                return true;
            });
            for (int i = 0; i < 5; i++) {
                access.create(new LwsPrincipal(CAROL, "iss", null), AccessService.Kind.GRANT,
                        grant(BOB, BASE + "/doc" + i).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            asked.set(0);
            access.grants(bob, BASE + "/nothing", AclMode.READ, java.time.Instant.now());
            assertEquals(1, asked.get(), "five grants from one issuer is one controller resolution");
        } finally {
            store.close();
        }
    }

    /** The census is what an operator inheriting a storage has instead of a hunch. */
    @Test
    void inertGrantsAreCounted() throws Exception {
        RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        try {
            List<String> controllers = new java.util.ArrayList<>(List.of(CAROL));
            AccessService access = accessService(store, controllers::contains);
            access.create(new LwsPrincipal(CAROL, "iss", null), AccessService.Kind.GRANT,
                    grant(BOB, BASE + "/doc").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            assertEquals(new AccessService.Census(1, 0), access.census());

            controllers.clear();
            assertEquals(new AccessService.Census(1, 1), access.census());
        } finally {
            store.close();
        }
    }

    /** Grant evaluation must never re-enter the authorizer that called it. */
    @Test
    void grantEvaluationAsksTheBaseAuthorizerAndNeverTheGrantAuthorizer() throws Exception {
        RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        try {
            AtomicInteger baseCalls = new AtomicInteger();
            Authorizer base = (principal, iri, mode) -> {
                baseCalls.incrementAndGet();
                return false; // nothing is permitted except through a grant
            };
            AccessService access = accessService(store, webId -> CAROL.equals(webId));
            access.create(new LwsPrincipal(CAROL, "iss", null), AccessService.Kind.GRANT,
                    grant(BOB, BASE + "/doc").getBytes(java.nio.charset.StandardCharsets.UTF_8));

            GrantAuthorizer authorizer = new GrantAuthorizer(base, access, config(), Clock.systemUTC());
            assertTrue(authorizer.allows(bob, BASE + "/doc", AclMode.READ));
            assertEquals(1, baseCalls.get(), "the base authorizer answers once, and is not re-entered");
        } finally {
            store.close();
        }
    }

    // ----- prior-review finding 12: grant evaluation cost -----

    /**
     * A check for one agent pulls back the grants that could apply to that agent, not every grant in
     * the storage.
     *
     * <p>Every evaluation used to {@code SELECT} every stored grant document and parse each one, so a
     * storage holding grants for many different agents did that work in full to answer a question
     * about one of them. Each grant now also stores its policies' assignees as triples and the query
     * filters on them — as an <em>index</em>: {@code assigneeMatches} still reads the assignee out of
     * the JSON, so the narrowing can only ever remove candidates, never admit one.
     *
     * <p>The observable consequence, and what this asserts: the issuer of a grant that names somebody
     * else is no longer consulted, because that grant is no longer a candidate. Against the pre-fix
     * code the controller predicate is called for every issuer of every grant.
     */
    @Test
    void aCheckOnlyConsidersGrantsThatCouldNameTheRequester() throws Exception {
        RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        try {
            AtomicInteger issuerChecks = new AtomicInteger();
            AccessService access = accessService(store, webId -> {
                issuerChecks.incrementAndGet();
                return CAROL.equals(webId);
            });
            LwsPrincipal carol = new LwsPrincipal(CAROL, "iss", null);
            // One grant for Bob, and twenty for agents who are not Bob.
            access.create(carol, AccessService.Kind.GRANT,
                    grant(BOB, BASE + "/doc").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            for (int i = 0; i < 20; i++) {
                access.create(carol, AccessService.Kind.GRANT,
                        grant("https://other" + i + ".example/#me", BASE + "/doc")
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }

            issuerChecks.set(0);
            assertTrue(access.grants(bob, BASE + "/doc", AclMode.READ, java.time.Instant.now()));
            assertTrue(issuerChecks.get() <= 1,
                    "only the grants that could name Bob are considered; consulted " + issuerChecks.get()
                            + " issuers out of 21 grants");
        } finally {
            store.close();
        }
    }

    /**
     * A grant naming the public applies to everyone, so it must survive the narrowing.
     *
     * <p>This is the arm that would fail closed if the filter were wrong — silently, and in the
     * direction that revokes rather than grants, which is why it is asserted separately.
     */
    @Test
    void aPublicGrantStillApplies() throws Exception {
        RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        try {
            AccessService access = accessService(store, CAROL::equals);
            access.create(new LwsPrincipal(CAROL, "iss", null), AccessService.Kind.GRANT,
                    grant("http://xmlns.com/foaf/0.1/Agent", BASE + "/doc")
                            .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            assertTrue(access.grants(bob, BASE + "/doc", AclMode.READ, java.time.Instant.now()),
                    "a foaf:Agent grant applies to any requester");
            assertTrue(access.grants(null, BASE + "/doc", AclMode.READ, java.time.Instant.now()),
                    "including an anonymous one");
        } finally {
            store.close();
        }
    }

    /**
     * A grant written before the index existed carries no assignee triples, and must go on being
     * evaluated exactly as it always was rather than silently ceasing to apply.
     *
     * <p>Simulated by writing the grant's document and creator directly, which is the shape an older
     * version of this server left in the store.
     */
    @Test
    void anUnindexedGrantIsStillEvaluated() throws Exception {
        RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        try {
            String id = BASE + "/.lws/access-grants/legacy";
            store.writeDo(conn -> {
                org.apache.jena.query.ParameterizedSparqlString u =
                        new org.apache.jena.query.ParameterizedSparqlString();
                u.setCommandText("INSERT DATA { GRAPH ?g { ?s a ?t . ?s ?creatorP ?creator . "
                        + "?s ?jsonP ?json } }");
                u.setIri("g", "urn:x-lws:access");
                u.setIri("s", id);
                u.setIri("t", "https://www.w3.org/ns/lws#AccessGrant");
                u.setIri("creatorP", "urn:x-lws:accessCreator");
                u.setIri("creator", CAROL);
                u.setIri("jsonP", "urn:x-lws:accessJson");
                u.setLiteral("json", grant(BOB, BASE + "/doc"));
                conn.update(u.asUpdate());
            });
            // Constructed after the grant is in the store, so it sees it as a legacy one.
            AccessService access = accessService(store, CAROL::equals);
            assertTrue(access.grants(bob, BASE + "/doc", AclMode.READ, java.time.Instant.now()),
                    "a grant written before the index existed must keep working");
        } finally {
            store.close();
        }
    }

    private static AccessService accessService(RdfStore store, Predicate<String> controllers) {
        return new AccessService(store, config(), new ResourceRegistry(), inbox -> true, controllers);
    }

    private static LwsConfiguration config() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.owners", "https://alice.example/profile#me");
        return LwsConfiguration.of(p);
    }

    private static String grant(String assignee, String target) {
        return "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessGrant\"], \"storage\":\""
                + BASE + "/\", \"access\":[{ \"type\":[\"AccessPolicy\"], \"action\":[\"read\"],"
                + " \"assignee\":\"" + assignee + "\", \"target\":{ \"type\":\"StorageResource\","
                + " \"value\":[\"" + target + "\"] } }] }";
    }
}
