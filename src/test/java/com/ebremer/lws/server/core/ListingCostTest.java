package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.apache.jena.rdfconnection.RDFConnection;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.TestDirs;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;

/**
 * What a container listing costs, in units the finding was written in (M23 and M39).
 *
 * <p>Reading a container used to open one store transaction for the membership and then <b>one more
 * per member</b>, because the authorization filter ran outside the read and every
 * {@code Authorizer.allows} opened its own: a fresh connection, a registry {@code CONSTRUCT} and a
 * commit under owner mode, and an ACL resolution per ancestor level under Web Access Control. A
 * thousand-member container was a thousand transactions; roughly six thousand at WAC depth five, all
 * serialized on the request thread. And every one of them was doing it to evaluate a predicate that,
 * for a configured owner or in open mode, could not have varied by resource.
 *
 * <p>These tests count transactions, which is the thing the finding is about — a wall-clock
 * assertion would be a flaky proxy for it.
 *
 * @author Erich Bremer
 */
class ListingCostTest {

    /**
     * A fresh data directory per test. Deleted on the way out where the platform allows it, and by
     * the next run's sweep where it does not — see {@link TestDirs}.
     */
    private final Path tempDir = TestDirs.create();

    private static final int MEMBERS = 25;

    /** An {@link RdfStore} that counts the units of work opened through it. */
    private static final class CountingStore implements RdfStore {

        private final RdfStore delegate;
        final AtomicInteger reads = new AtomicInteger();
        final AtomicInteger writes = new AtomicInteger();

        CountingStore(RdfStore delegate) {
            this.delegate = delegate;
        }

        @Override
        public <T> T read(Function<RDFConnection, T> action) {
            reads.incrementAndGet();
            return delegate.read(action);
        }

        @Override
        public <T> T write(Function<RDFConnection, T> action) {
            writes.incrementAndGet();
            return delegate.write(action);
        }

        @Override
        public boolean inUnitOfWork() {
            return delegate.inUnitOfWork();
        }

        @Override
        public void close() {
            delegate.close();
        }
    }

    /**
     * A per-resource authorizer — the Web Access Control shape, which cannot answer for the whole
     * storage at once — must still see the whole listing in <em>one</em> transaction.
     *
     * <p>Against the pre-fix code this is {@code MEMBERS} transactions plus the enumeration, because
     * the filter ran outside the read and each {@code allows} opened its own. The assertion is a
     * small constant rather than an exact number so it does not have to be rewritten every time an
     * unrelated lookup is added, but it is far below {@code MEMBERS} and that is the point.
     */
    @Test
    void aPerResourceAuthorizerStillCostsOneTransactionForTheWholeListing() throws Exception {
        LwsConfiguration config = config();
        CountingStore store = new CountingStore(new Tdb2RdfStore(config.tdb2Dir()));
        try {
            // Per-resource by construction: the answer depends on the IRI, so allowsEverything is
            // false and every member really is asked about.
            List<String> asked = new ArrayList<>();
            Authorizer authorizer = new Authorizer() {
                @Override
                public boolean allows(LwsPrincipal principal, String targetIri, AclMode mode) {
                    if (mode == AclMode.READ) {
                        asked.add(targetIri);
                    }
                    return true;
                }
            };
            ResourceService service = service(store, config, authorizer);
            populate(service);

            store.reads.set(0);
            List<ResourceRegistry.ChildRef> visible = service.read("/c/", owner()).children();
            assertEquals(MEMBERS, visible.size());
            assertTrue(asked.size() >= MEMBERS, "every member is authorized: " + asked.size());
            assertTrue(store.reads.get() <= 3,
                    "the whole listing must fit in one unit of work, not one per member; opened "
                            + store.reads.get() + " for " + MEMBERS + " members");
        } finally {
            store.close();
        }
    }

    /**
     * Where the authorizer's answer cannot vary by resource — a configured owner, open mode, a
     * public-read storage — the per-member loop is skipped outright.
     *
     * <p>This is the ordinary deployment, and it turns an O(members) sweep into O(1). It fails
     * against the pre-fix code, which had no way to ask the question and called {@code allows} once
     * per member unconditionally.
     */
    @Test
    void aUniformAuthorizerIsNotAskedPerMember() throws Exception {
        LwsConfiguration config = config();
        CountingStore store = new CountingStore(new Tdb2RdfStore(config.tdb2Dir()));
        try {
            AtomicInteger perMember = new AtomicInteger();
            Authorizer authorizer = new Authorizer() {
                @Override
                public boolean allows(LwsPrincipal principal, String targetIri, AclMode mode) {
                    perMember.incrementAndGet();
                    return true;
                }

                @Override
                public boolean allowsEverything(LwsPrincipal principal, AclMode mode) {
                    return mode == AclMode.READ;
                }
            };
            ResourceService service = service(store, config, authorizer);
            populate(service);

            perMember.set(0);
            assertEquals(MEMBERS, service.read("/c/", owner()).children().size());
            // One: the container itself, which is authorized whatever the members cost.
            assertTrue(perMember.get() <= 1,
                    "a uniform answer must not be asked for once per member; asked "
                            + perMember.get() + " times for " + MEMBERS + " members");
        } finally {
            store.close();
        }
    }

    /**
     * A page's listing metadata is fetched for that page's members, not for the whole membership.
     *
     * <p>{@code describe} keeps the containment constraint, so naming something that is not a member
     * of this container yields nothing for it — the method is "describe these members", not
     * "describe any IRI you name".
     */
    @Test
    void describeFetchesOnlyTheNamedMembersAndOnlyRealOnes() throws Exception {
        LwsConfiguration config = config();
        RdfStore store = new Tdb2RdfStore(config.tdb2Dir());
        try {
            ResourceService service = service(store, config,
                    (principal, iri, mode) -> true);
            populate(service);

            List<String> all = service.read("/c/", owner()).children().stream()
                    .map(ResourceRegistry.ChildRef::iri).toList();
            List<String> window = all.subList(0, 5);
            List<ResourceRegistry.ChildDesc> described = service.describe("http://example.org/c/", window);
            assertEquals(window, described.stream().map(ResourceRegistry.ChildDesc::iri).toList(),
                    "the caller's page order is preserved");
            assertEquals("text/plain", described.get(0).mediaType());

            List<ResourceRegistry.ChildDesc> outsider = service.describe("http://example.org/c/",
                    List.of("http://example.org/elsewhere"));
            assertTrue(outsider.isEmpty(), "an IRI that is not a member of this container is not described");
        } finally {
            store.close();
        }
    }

    // ----- fixture -----

    private LwsConfiguration config() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://example.org");
        p.setProperty("lws.owners", "http://example.org/owner");
        p.setProperty("lws.data-dir", tempDir.toString());
        return LwsConfiguration.of(p);
    }

    private static LwsPrincipal owner() {
        return new LwsPrincipal("http://example.org/owner", null, null);
    }

    private static ResourceService service(RdfStore store, LwsConfiguration config, Authorizer authorizer) {
        ResourceService service = new ResourceService(store, new FileSystemBinaryStore(config.blobDir()),
                new ResourceRegistry(), authorizer, config, Clock.systemUTC());
        service.ensureStorageRoot();
        return service;
    }

    private static void populate(ResourceService service) {
        LwsPrincipal owner = owner();
        service.create("/", owner, new ResourceService.WriteRequest(null, new byte[0],
                ResourceService.TypeHint.CONTAINER, "c"));
        for (int i = 0; i < MEMBERS; i++) {
            service.create("/c/", owner, new ResourceService.WriteRequest("text/plain",
                    ("m" + i).getBytes(), ResourceService.TypeHint.AUTO, "member" + i));
        }
    }
}
