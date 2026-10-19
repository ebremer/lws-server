package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.rdf.model.Model;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.ResourceService.TypeHint;
import com.ebremer.lws.server.core.ResourceService.WriteRequest;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;

/**
 * Moving resources between containers by changing the {@code up} link of their linkset
 * (lws10-core, Moving Resources), below the HTTP layer: what may be moved, by whom, what moves with
 * it, what a previous IRI answers, and what the rest of the server is told.
 *
 * <p>The authorizer here is a table, so that each of the two authorizations the draft requires —
 * the delete resource operation on what moves (for a container, on all of it) and the create
 * resource operation in the destination — can be withheld on its own. Web Access Control cannot
 * express that split ({@code acl:Write} is both), which is exactly why it has to be tested here.
 *
 * @author Erich Bremer
 */
class MoveResourceServiceTest {

    private static final String BASE = "http://example.org";
    private static final LwsPrincipal ALICE = new LwsPrincipal("https://alice.example/profile#me", "iss", null);

    @TempDir
    Path dir;

    /** Every component a move touches, over one in-memory store. */
    private final class Stack {
        final Tdb2RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        final List<String[]> denied = new ArrayList<>();
        final List<String> preparedInsideATransaction = new ArrayList<>();
        final List<String> prepared = new ArrayList<>();
        final List<ResourceEvent> events = new ArrayList<>();
        final ResourceService rs;
        final LinksetService linksets;
        final SearchIndexService index;

        Stack(String appliesTo) {
            Properties p = new Properties();
            p.setProperty("lws.base-uri", BASE);
            p.setProperty("lws.owners", ALICE.webId());
            p.setProperty("lws.data-dir", dir.toString());
            if (appliesTo != null) {
                p.setProperty("lws.move.applies-to", appliesTo);
            }
            LwsConfiguration config = LwsConfiguration.of(p);
            Authorizer table = new Authorizer() {
                @Override
                public boolean allows(LwsPrincipal principal, String iri, AclMode mode) {
                    return denied.stream().noneMatch(d -> d[0].equals(iri) && d[1].equals(mode.name()));
                }

                @Override
                public void prepare(LwsPrincipal principal, String iri, AclMode mode) {
                    prepared.add(mode + " " + iri);
                    if (store.inUnitOfWork()) {
                        preparedInsideATransaction.add(mode + " " + iri);
                    }
                }
            };
            rs = new ResourceService(store, new FileSystemBinaryStore(config.blobDir()), new ResourceRegistry(),
                    table, config, Clock.systemUTC());
            rs.ensureStorageRoot();
            linksets = new LinksetService(store, rs, config);
            rs.addDeleteCleanup(linksets);
            rs.addRelocation(linksets);
            index = new SearchIndexService(store, table);
            index.setLinksets(linksets);
            linksets.setMetadataListener(index::onMetadataChanged);
            rs.addEventListener(index);
            rs.addEventListener(events::add);
        }

        void deny(String path, AclMode mode) {
            denied.add(new String[] {BASE + path, mode.name()});
        }

        void container(String path) {
            rs.put(path, ALICE, new WriteRequest(null, new byte[0], TypeHint.CONTAINER, null));
        }

        void text(String path, String body) {
            rs.put(path, ALICE, new WriteRequest("text/plain", body.getBytes(StandardCharsets.UTF_8),
                    TypeHint.AUTO, null));
        }

        void turtle(String path, String body) {
            rs.put(path, ALICE, new WriteRequest("text/turtle", body.getBytes(StandardCharsets.UTF_8),
                    TypeHint.AUTO, null));
        }

        /** The draft's move: replace the up link's href in the resource's linkset document. */
        LinksetService.Linkset move(String path, String destination) {
            return patch(path, "[{\"op\":\"replace\",\"path\":\"/linkset/0/up/0/href\",\"value\":\""
                    + destination + "\"}]");
        }

        LinksetService.Linkset patch(String path, String jsonPatch) {
            return linksets.jsonPatch(path, jsonPatch.getBytes(StandardCharsets.UTF_8), IfMatch.NONE, ALICE);
        }

        boolean exists(String path) {
            return rs.stat(path).isPresent();
        }

        String etag(String path) {
            return rs.stat(path).orElseThrow().etag();
        }

        List<String> members(String path) {
            return rs.read(path, ALICE).children().stream().map(c -> c.iri()).toList();
        }
    }

    // ----- what is configured -----

    /** Touchstone move-refused-without-capability: no MoveResource, so no move, and 409. */
    @Test
    void withMovingOffEveryUpChangeIsRefusedAndNothingChanges() {
        Stack s = new Stack("none");
        s.container("/a/");
        s.container("/b/");
        s.text("/a/x", "stays put");
        String linkset = s.linksets.get("/a/x").etag();

        LwsException replaced = assertThrows(LwsException.class, () -> s.move("/a/x", BASE + "/b/"));
        assertEquals(409, replaced.status());
        LwsException added = assertThrows(LwsException.class, () -> s.patch("/a/x",
                "[{\"op\":\"add\",\"path\":\"/linkset/0/up\",\"value\":[{\"href\":\"" + BASE + "/b/\"}]}]"));
        assertEquals(409, added.status(), "the form Touchstone sends, which used to answer 204 having moved nothing");

        assertTrue(s.exists("/a/x"));
        assertFalse(s.exists("/b/x"));
        assertEquals(List.of(), s.members("/b/"));
        assertEquals(linkset, s.linksets.get("/a/x").etag(), "and the linkset is as it was");
        // The up link it already has is not a move, so an ordinary write goes on as before.
        assertFalse(s.patch("/a/x", "[{\"op\":\"add\",\"path\":\"/linkset/0/license\","
                + "\"value\":[{\"href\":\"https://example.org/l\"}]}]").moved());
    }

    @Test
    void aStorageThatMovesOnlyDataResourcesRefusesToMoveAContainer() {
        Stack s = new Stack("DataResource");
        s.container("/a/");
        s.container("/a/c/");
        s.container("/b/");
        s.text("/a/x", "x");

        assertEquals(409, assertThrows(LwsException.class, () -> s.move("/a/c/", BASE + "/b/")).status());
        assertTrue(s.exists("/a/c/"));
        assertTrue(s.move("/a/x", BASE + "/b/").moved(), "a data resource still moves");
    }

    // ----- what moves -----

    @Test
    void aMovedDataResourceKeepsItsNameContentMetadataAndOwner() throws Exception {
        Stack s = new Stack(null);
        s.container("/a/");
        s.container("/b/");
        s.text("/a/note.txt", "content that travels unchanged");
        s.patch("/a/note.txt", "[{\"op\":\"add\",\"path\":\"/linkset/0/license\","
                + "\"value\":[{\"href\":\"https://creativecommons.org/licenses/by/4.0/\"}]}]");
        LwsResource before = s.rs.stat("/a/note.txt").orElseThrow();
        String sourceTag = s.etag("/a/");
        String destinationTag = s.etag("/b/");

        LinksetService.Linkset moved = s.move("/a/note.txt", "../b/"); // relative to the linkset's URL

        assertEquals(BASE + "/b/note.txt", moved.movedTo());
        JsonObject context = Json.createReader(new StringReader(moved.json())).readObject()
                .getJsonArray("linkset").getJsonObject(0);
        assertEquals(BASE + "/b/note.txt", context.getString("anchor"), "the anchor is the new identifier");
        assertEquals(BASE + "/b/", context.getJsonArray("up").getJsonObject(0).getString("href"));
        assertEquals(BASE + "/b/note.txt.meta", context.getJsonArray("linkset").getJsonObject(0).getString("href"));
        assertEquals("https://creativecommons.org/licenses/by/4.0/",
                context.getJsonArray("license").getJsonObject(0).getString("href"), "user metadata moved with it");
        assertEquals(moved.etag(), s.linksets.get("/b/note.txt").etag());

        LwsResource after = s.rs.stat("/b/note.txt").orElseThrow();
        assertEquals(BASE + "/b/", after.parentIri());
        assertEquals(before.etag(), after.etag(), "the content did not change, so neither did its tag");
        assertEquals(before.created(), after.created());
        assertEquals(before.owner(), after.owner());
        try (var in = s.rs.openBinary(after)) {
            assertEquals("content that travels unchanged", new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
        assertFalse(s.exists("/a/note.txt"));
        assertEquals(List.of(), s.members("/a/"));
        assertEquals(List.of(BASE + "/b/note.txt"), s.members("/b/"));
        assertNotEquals(sourceTag, s.etag("/a/"), "the container it left has a new tag");
        assertNotEquals(destinationTag, s.etag("/b/"), "and so has the one it joined");
    }

    @Test
    void aMovedContainerTakesItsWholeSubtreeContentAndMetadataAlong() {
        Stack s = new Stack(null);
        s.container("/a/");
        s.container("/b/");
        s.container("/a/c/");
        s.container("/a/c/d/");
        s.turtle("/a/c/d/doc.ttl", "<#it> <http://schema.org/name> \"deep\" .");
        s.text("/a/c/x.txt", "x");
        s.patch("/a/c/d/doc.ttl", "[{\"op\":\"add\",\"path\":\"/linkset/0/describedby\","
                + "\"value\":[{\"href\":\"https://shapes.example/S\"}]}]");
        s.events.clear();

        assertEquals(BASE + "/b/c/", s.move("/a/c/", BASE + "/b/").movedTo());

        for (String gone : List.of("/a/c/", "/a/c/d/", "/a/c/d/doc.ttl", "/a/c/x.txt")) {
            assertFalse(s.exists(gone), gone);
        }
        assertEquals(List.of(BASE + "/b/c/d/", BASE + "/b/c/x.txt"), s.members("/b/c/"));
        assertEquals(List.of(BASE + "/b/c/d/doc.ttl"), s.members("/b/c/d/"));
        assertEquals(BASE + "/b/c/d/", s.rs.stat("/b/c/d/doc.ttl").orElseThrow().parentIri());

        // An RDF source's content graph is named by its IRI, so it moved too — and was not rebased:
        // the triple about <#it> still names it under the IRI it was parsed against.
        Model content = s.rs.read("/b/c/d/doc.ttl", ALICE).rdf();
        assertTrue(content.contains(content.getResource(BASE + "/a/c/d/doc.ttl#it"), null, "deep"),
                content.toString());
        boolean leftBehind = s.store.read(conn -> !conn.fetch(BASE + "/a/c/d/doc.ttl").isEmpty());
        assertFalse(leftBehind, "nothing left at the old name");
        assertTrue(s.linksets.get("/b/c/d/doc.ttl").json().contains("https://shapes.example/S"),
                "a descendant's metadata moved with it");

        // One activity for the move, about the container; its descendants raise none of their own.
        assertEquals(1, s.events.size(), s.events.toString());
        ResourceEvent move = s.events.get(0);
        assertEquals(ActivityKind.MOVE, move.kind());
        assertEquals(BASE + "/b/c/", move.iri());
        assertEquals(BASE + "/a/c/", move.previousIri());
        assertEquals(BASE + "/a/", move.origin());
        assertEquals(BASE + "/b/", move.target());
    }

    @Test
    void aNameTakenInTheDestinationIsNotOverwritten() throws Exception {
        Stack s = new Stack(null);
        s.container("/a/");
        s.container("/b/");
        s.text("/a/note.txt", "moving");
        s.text("/b/note.txt", "already here");

        String moved = s.move("/a/note.txt", BASE + "/b/").movedTo();

        assertNotEquals(BASE + "/b/note.txt", moved);
        assertTrue(moved.startsWith(BASE + "/b/note.txt-"), moved);
        try (var in = s.rs.openBinary(s.rs.stat("/b/note.txt").orElseThrow())) {
            assertEquals("already here", new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
        assertEquals(2, s.members("/b/").size());
    }

    // ----- what is refused -----

    @Test
    void anUpThatNamesNoContainerOfThisStorageIsRefused() {
        Stack s = new Stack(null);
        s.container("/a/");
        s.text("/a/x", "x");
        s.text("/other", "a data resource is no container");

        assertEquals(404, assertThrows(LwsException.class, () -> s.move("/a/x", BASE + "/nowhere/")).status());
        assertEquals(409, assertThrows(LwsException.class, () -> s.move("/a/x", BASE + "/other")).status());
        assertEquals(409, assertThrows(LwsException.class,
                () -> s.move("/a/x", "https://elsewhere.example/c/")).status(), "another storage");
        assertEquals(409, assertThrows(LwsException.class,
                () -> s.patch("/a/x", "[{\"op\":\"remove\",\"path\":\"/linkset/0/up\"}]")).status(),
                "no resource but the root may be left without an up link");
        assertEquals(409, assertThrows(LwsException.class, () -> s.patch("/a/x",
                "[{\"op\":\"add\",\"path\":\"/linkset/0/up/-\",\"value\":{\"href\":\"" + BASE + "/\"}}]")).status(),
                "two ups");
        assertEquals(422, assertThrows(LwsException.class, () -> s.patch("/a/x",
                "[{\"op\":\"replace\",\"path\":\"/linkset/0/up\",\"value\":\"" + BASE + "/\"}]")).status(),
                "an up that is not a link target array is malformed");
        assertEquals(409, assertThrows(LwsException.class, () -> s.patch("/",
                "[{\"op\":\"add\",\"path\":\"/linkset/0/up\",\"value\":[{\"href\":\"" + BASE + "/a/\"}]}]")).status(),
                "the root is in no container");
        assertEquals(409, assertThrows(LwsException.class, () -> s.linksets.jsonPatch("/a/x",
                "[{\"op\":\"add\",\"path\":\"/up\",\"value\":[{\"href\":\"x\"}]}]".getBytes(StandardCharsets.UTF_8),
                IfMatch.NONE, ALICE)).status(), "the relation map never holds up");
        assertTrue(s.exists("/a/x"));
    }

    @Test
    void aContainerCannotMoveIntoItselfOrItsOwnDescendant() {
        Stack s = new Stack(null);
        s.container("/outer/");
        s.container("/outer/inner/");

        LwsException into = assertThrows(LwsException.class, () -> s.move("/outer/", BASE + "/outer/inner/"));
        assertEquals(409, into.status());
        assertEquals("Cannot move a container into one of its own descendants", into.title());
        assertEquals(BASE + "/outer/inner/ is a descendant of " + BASE + "/outer/", into.getMessage());
        assertEquals(409, assertThrows(LwsException.class, () -> s.move("/outer/", BASE + "/outer/")).status());
        assertTrue(s.exists("/outer/inner/"));
        assertEquals(BASE + "/", s.rs.stat("/outer/").orElseThrow().parentIri());
    }

    // ----- who may move what -----

    @Test
    void mayWriteTheLinksetButNotDeleteTheResource() {
        Stack s = new Stack(null);
        s.container("/a/");
        s.container("/b/");
        s.text("/a/x", "x");
        s.deny("/a/x", AclMode.DELETE);

        assertEquals(403, assertThrows(LwsException.class, () -> s.move("/a/x", BASE + "/b/")).status());
        assertTrue(s.exists("/a/x"));
        assertEquals(List.of(), s.members("/b/"));
    }

    @Test
    void mayNotCreateInTheDestination() {
        Stack s = new Stack(null);
        s.container("/a/");
        s.container("/b/");
        s.text("/a/x", "x");
        s.deny("/b/", AclMode.APPEND);

        assertEquals(403, assertThrows(LwsException.class, () -> s.move("/a/x", BASE + "/b/")).status());
        assertTrue(s.exists("/a/x"));
        assertEquals(List.of(), s.members("/b/"));
    }

    /** For a container the authorization is that of a recursive delete: all of it, or none of it moves. */
    @Test
    void aContainerWithADescendantTheAgentMayNotDeleteDoesNotMoveAtAll() {
        Stack s = new Stack(null);
        s.container("/a/");
        s.container("/b/");
        s.container("/a/c/");
        s.container("/a/c/d/");
        s.text("/a/c/free", "may go");
        s.text("/a/c/d/pinned", "may not");
        s.deny("/a/c/d/pinned", AclMode.DELETE);

        assertEquals(403, assertThrows(LwsException.class, () -> s.move("/a/c/", BASE + "/b/")).status());
        for (String still : List.of("/a/c/", "/a/c/free", "/a/c/d/", "/a/c/d/pinned")) {
            assertTrue(s.exists(still), still);
        }
        assertEquals(List.of(), s.members("/b/"));
    }

    /**
     * H16: nothing may fetch over the network with the writer lock held, so every authorization a
     * move makes — DELETE on each member of the subtree, APPEND on the destination — is warmed
     * before its write transaction opens, the way a recursive delete warms its own.
     */
    @Test
    void everyAuthorizationAMoveMakesIsWarmedOutsideTheTransaction() {
        Stack s = new Stack(null);
        s.container("/a/");
        s.container("/b/");
        s.container("/a/c/");
        s.text("/a/c/x", "x");
        s.prepared.clear();

        s.move("/a/c/", BASE + "/b/");

        assertTrue(s.prepared.containsAll(List.of("DELETE " + BASE + "/a/c/", "DELETE " + BASE + "/a/c/x",
                "APPEND " + BASE + "/b/")), s.prepared.toString());
        assertEquals(List.of(), s.preparedInsideATransaction);
    }

    // ----- what a previous IRI answers -----

    @Test
    void aPreviousIriLeadsToWhereTheResourceIsNow() {
        Stack s = new Stack(null);
        s.container("/a/");
        s.container("/b/");
        s.container("/c/");
        s.container("/a/sub/");
        s.text("/a/sub/x", "x");
        s.text("/a/sub/y", "y");

        // A resource moved out of a container before the container itself moves...
        s.move("/a/sub/y", BASE + "/c/");
        s.move("/a/sub/", BASE + "/b/");
        assertEquals(Optional.of(BASE + "/b/sub/"), movedTo(s, "/a/sub/"));
        assertEquals(Optional.of(BASE + "/b/sub/x"), movedTo(s, "/a/sub/x"), "a descendant, by prefix");
        assertEquals(Optional.of(BASE + "/c/y"), movedTo(s, "/a/sub/y"), "...is still found where it went");
        assertEquals(Optional.empty(), movedTo(s, "/a/sub/never-was"), "only what exists is pointed at");

        // Moved again: the previous IRIs lead straight to the current one.
        s.move("/b/sub/", BASE + "/c/");
        assertEquals(Optional.of(BASE + "/c/sub/x"), movedTo(s, "/a/sub/x"));
        assertEquals(Optional.of(BASE + "/c/sub/x"), movedTo(s, "/b/sub/x"));

        // Moved back where it started: nothing redirects there, and the last place leads home.
        s.move("/c/sub/", BASE + "/a/");
        assertEquals(Optional.empty(), movedTo(s, "/a/sub/x"), "something is stored there");
        assertEquals(Optional.of(BASE + "/a/sub/x"), movedTo(s, "/c/sub/x"));

        assertEquals(Optional.of(BASE + "/c/y"), movedTo(s, "/a/sub/y"), "y did not come back with it");

        // A resource created at a previous IRI takes precedence, over that IRI and what is under it.
        s.container("/c/sub/");
        assertEquals(Optional.empty(), movedTo(s, "/c/sub/"));
        assertEquals(Optional.empty(), movedTo(s, "/c/sub/x"), "/c/sub/ is another container now");
        // And a deleted resource is pointed at by nothing.
        s.rs.delete("/c/y", ALICE);
        assertEquals(Optional.empty(), movedTo(s, "/a/sub/y"));
    }

    @Test
    void aPreviousIriIsPointedOutOnlyToWhoeverMayReadTheResourceNow() {
        Stack s = new Stack(null);
        s.container("/a/");
        s.container("/b/");
        s.text("/a/x", "x");
        s.move("/a/x", BASE + "/b/");
        s.deny("/b/x", AclMode.READ);

        assertEquals(Optional.empty(), movedTo(s, "/a/x"));
        assertEquals(Optional.of(BASE + "/b/x"), s.rs.movedTo(BASE + "/a/x", ALICE, AclMode.WRITE));
    }

    // ----- what the search index says -----

    @Test
    void theSearchIndexFindsAMovedResourceAtItsNewIriOnly() {
        Stack s = new Stack(null);
        s.container("/a/");
        s.container("/b/");
        s.container("/a/c/");
        s.text("/a/c/x", "x");
        s.patch("/a/c/x", "[{\"op\":\"add\",\"path\":\"/linkset/0/type/-\","
                + "\"value\":{\"href\":\"https://schema.org/Recipe\"}}]");
        assertTrue(s.index.typesOf(BASE + "/a/c/x").contains("https://schema.org/Recipe")); // builds the index

        s.move("/a/c/", BASE + "/b/");

        assertEquals(Set.of(), s.index.typesOf(BASE + "/a/c/x"));
        assertEquals(Set.of(), s.index.typesOf(BASE + "/a/c/"));
        assertTrue(s.index.typesOf(BASE + "/b/c/x").containsAll(
                Set.of("https://schema.org/Recipe", "https://www.w3.org/ns/lws#DataResource")));
        assertTrue(s.index.typesOf(BASE + "/b/c/").contains("https://www.w3.org/ns/lws#Container"));
        SearchIndexService.Filter recipes = new SearchIndexService.Filter(
                List.of(SearchIndexService.Clause.type(List.of("https://schema.org/Recipe"))));
        List<String> found = s.index.typeSearch(ALICE, recipes, 1, 10).items().stream()
                .map(SearchIndexService.Match::iri).toList();
        assertEquals(List.of(BASE + "/b/c/x"), found);
    }

    private static Optional<String> movedTo(Stack s, String path) {
        return s.rs.movedTo(BASE + path, ALICE, AclMode.READ);
    }
}
