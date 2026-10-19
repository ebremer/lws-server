package com.ebremer.lws.server.rdf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFFormat;
import org.apache.jena.riot.RIOT;
import org.apache.jena.riot.lang.LangJSONLD11;
import org.apache.jena.vocabulary.DCTerms;
import org.apache.jena.vocabulary.RDF;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Finding N1 — the JSON-LD {@code @context} policy, and the two things that were wrong with it.
 *
 * <p>A JSON-LD body chooses its own {@code @context}, so resolving one makes the server fetch a URL
 * the document picked. That is refused by default. An operator may allow specific hosts through
 * {@code lws.jsonld.allowed-context-hosts} — and two separate defects sat on that path.
 *
 * @author Erich Bremer
 */
class JsonLdContextPolicyTest {

    private static final String BODY = """
            {"@context":"https://ctx.example/v1","@id":"http://example.org/s","name":"x"}
            """;

    @AfterEach
    void restoreTheRefuseAllDefault() {
        JsonLdSecurity.setTransactionProbe(null);
        JsonLdSecurity.install(Set.of());
    }

    /**
     * The measured bug, and the reason {@code installDefault} is now conditional.
     *
     * <p>{@code RdfIO}'s static initializer installs the refuse-all default, and a static
     * initializer runs on first <em>use</em> of the class. In the assembled server that is
     * <em>after</em> {@code LwsComponents} has installed the operator's allow-list, because nothing
     * touches {@code RdfIO} until the storage root is ensured. So the first RDF operation of the
     * process silently replaced the configured policy with refuse-all, and
     * {@code lws.jsonld.allowed-context-hosts} was a documented configuration key that did nothing
     * at all. Measured directly: the installed options object was a different instance afterwards.
     */
    @Test
    void anOperatorAllowListIsNotDiscardedWhenRdfIoIsFirstUsed() {
        JsonLdSecurity.install(Set.of("ctx.example"));
        Object afterInstall = RIOT.getContext().get(LangJSONLD11.JSONLD_OPTIONS);
        assertNotNull(afterInstall, "install must put a policy in the RIOT context");

        // Any use of RdfIO triggers its static initializer, which installs the default.
        RdfIO.writeString(ModelFactory.createDefaultModel(), RDFFormat.NTRIPLES);

        assertSame(afterInstall, RIOT.getContext().get(LangJSONLD11.JSONLD_OPTIONS),
                "the operator's JSON-LD context policy was replaced by the refuse-all default");
    }

    /** An explicit install still wins in the other order, so neither startup sequence loses it. */
    @Test
    void anExplicitInstallOverridesTheDefaultInEitherOrder() {
        JsonLdSecurity.installDefault();
        JsonLdSecurity.install(Set.of("ctx.example"));
        Object explicit = RIOT.getContext().get(LangJSONLD11.JSONLD_OPTIONS);
        JsonLdSecurity.installDefault();
        assertSame(explicit, RIOT.getContext().get(LangJSONLD11.JSONLD_OPTIONS));
    }

    /** With no allow-list, a remote context is refused outright and no socket is ever opened. */
    @Test
    void aRemoteContextIsRefusedByDefault() {
        JsonLdSecurity.install(Set.of());
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> RdfIO.parse(BODY.getBytes(StandardCharsets.UTF_8), Lang.JSONLD,
                        "http://example.org/s"));
        assertTrue(e.getMessage().contains("not permitted"), e.getMessage());
        assertTrue(e.getMessage().contains("lws.jsonld.allowed-context-hosts"), e.getMessage());
    }

    /**
     * Finding N1 proper. An RDF write parses its body <em>inside</em> the write transaction — for a
     * POST the base IRI is only chosen in there — and the store admits one writer for the whole
     * storage. So a context fetch from in there holds that writer lock for as long as the remote
     * host cares to take. This is H16's harm by a path H16 did not cover, and it needs no WAC: an
     * operator following this project's own example configuration was one client PUT away from it.
     *
     * <p>Refused, not merely time-bounded: a tighter timeout still holds the lock. The refusal names
     * the situation rather than the allow-list, so an operator can tell the two cases apart.
     */
    @Test
    void anAllowedRemoteContextIsStillRefusedWhileAStoreTransactionIsOpen() {
        JsonLdSecurity.install(Set.of("ctx.example"));
        JsonLdSecurity.setTransactionProbe(() -> true);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> RdfIO.parse(BODY.getBytes(StandardCharsets.UTF_8), Lang.JSONLD,
                        "http://example.org/s"));
        assertTrue(e.getMessage().contains("while storing a resource"),
                () -> "refused for the wrong reason: " + e.getMessage());
        // ...and it is refused before any network call, so nothing here depends on DNS.
        assertTrue(e.getMessage().contains("ctx.example"), e.getMessage());
    }

    /** A probe that throws is read as "no transaction" rather than failing the parse. */
    @Test
    void aFailingTransactionProbeDoesNotBreakParsing() {
        JsonLdSecurity.install(Set.of());
        JsonLdSecurity.setTransactionProbe(() -> {
            throw new IllegalStateException("the store this probe named is closed");
        });
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> RdfIO.parse(BODY.getBytes(StandardCharsets.UTF_8), Lang.JSONLD,
                        "http://example.org/s"));
        assertTrue(e.getMessage().contains("not permitted"),
                () -> "the allow-list check must still be the one that refused: " + e.getMessage());
    }

    /**
     * The LWS context ({@code https://www.w3.org/ns/lws/v1}) is answered from the copy bundled with
     * the server, in every posture, and never fetched — the URL still answers 404, and a container's
     * RDF representations are read through it on every request.
     *
     * <p>This would fail if it were fetched: with the refuse-all default a fetch is refused outright,
     * and with its host allowed but a transaction open it is refused before any socket is opened.
     * Both refusals name the URL, which the parse here must not see.
     */
    @Test
    void theBundledLwsContextResolvesWithoutTheNetwork() {
        String container = """
                {"@context":"https://www.w3.org/ns/lws/v1","id":"https://s.example/c/","type":"Container",
                 "totalItems":2,"items":[
                   {"type":"DataResource","id":"https://s.example/c/a","format":"text/plain","size":8,
                    "modified":"2026-10-19T12:00:00Z"},
                   {"type":"Container","id":"https://s.example/c/d/","modified":"2026-10-19T12:00:00Z"}]}
                """;
        String lws = "https://www.w3.org/ns/lws#";
        for (Set<String> allowed : List.of(Set.<String>of(), Set.of("www.w3.org"))) {
            JsonLdSecurity.install(allowed);
            JsonLdSecurity.setTransactionProbe(() -> true);
            Model m = RdfIO.parse(container.getBytes(StandardCharsets.UTF_8), Lang.JSONLD, "https://s.example/c/");
            Resource c = m.createResource("https://s.example/c/");
            Resource a = m.createResource("https://s.example/c/a");
            Resource d = m.createResource("https://s.example/c/d/");
            assertTrue(m.contains(c, RDF.type, m.createResource(lws + "Container")), allowed.toString());
            assertTrue(m.contains(c, m.createProperty(lws + "items"), a));
            assertTrue(m.contains(c, m.createProperty(lws + "totalItems"), m.createTypedLiteral(
                    "2", XSDDatatype.XSDinteger)));
            assertTrue(m.contains(a, DCTerms.format, "text/plain"));
            assertTrue(m.contains(a, m.createProperty("http://schema.org/size"),
                    m.createTypedLiteral("8", XSDDatatype.XSDlong)));
            assertTrue(m.contains(a, DCTerms.modified,
                    m.createTypedLiteral("2026-10-19T12:00:00Z", XSDDatatype.XSDdateTime)));
            // The context scopes `modified` to a DataResource, so a contained container's is not RDF.
            assertFalse(m.contains(d, DCTerms.modified), "modified is not a Container term");
            assertEquals(9, m.size(), () -> RdfIO.writeString(m, RDFFormat.NTRIPLES));
        }
    }

    /**
     * The bundled file is the Working Group's build of the vocabulary's context, byte for byte. A
     * copy edited by hand would let this server's RDF of a container and a client's reading of the
     * same lws+json disagree, so a change to it has to be a deliberate replacement, which updates
     * this digest too.
     */
    @Test
    void theBundledLwsContextIsTheWorkingGroupsBuildUnmodified() throws Exception {
        try (InputStream in = JsonLdSecurity.class.getResourceAsStream("/contexts/lws-v1.jsonld")) {
            assertNotNull(in, "the LWS context is not on the classpath");
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(in.readAllBytes());
            assertEquals("b2dda589fea8bb68cdd8f741c46f60e0f439dd303d6765a94498031b18033e50",
                    HexFormat.of().formatHex(digest));
        }
    }

    /**
     * Bundling the context makes documents that name it parse, and nothing else changes: the context
     * is {@code @protected}, so a document that redefines one of its terms is still refused, as the
     * JSON-LD processor refuses any protected-term redefinition.
     */
    @Test
    void theLwsContextsProtectedTermsCannotBeRedefined() {
        JsonLdSecurity.install(Set.of());
        String redefined = """
                {"@context":["https://www.w3.org/ns/lws/v1",{"topic":"http://example.org/notTheTopic"}],
                 "id":"https://s.example/x","topic":"https://s.example/"}
                """;
        assertThrows(IllegalArgumentException.class, () -> RdfIO.parse(
                redefined.getBytes(StandardCharsets.UTF_8), Lang.JSONLD, "https://s.example/x"));
    }

    /** An inline context needs no fetch, so it works in every posture, transaction or not. */
    @Test
    void anInlineContextParsesEvenInsideATransaction() {
        JsonLdSecurity.install(Set.of());
        JsonLdSecurity.setTransactionProbe(() -> true);
        String inline = """
                {"@context":{"name":"http://schema.org/name"},
                 "@id":"http://example.org/s","name":"x"}
                """;
        assertEquals(1, RdfIO.parse(inline.getBytes(StandardCharsets.UTF_8), Lang.JSONLD,
                "http://example.org/s").size());
    }
}
