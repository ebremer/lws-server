package com.ebremer.lws.server.rdf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFFormat;
import org.apache.jena.riot.RIOT;
import org.apache.jena.riot.lang.LangJSONLD11;
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
