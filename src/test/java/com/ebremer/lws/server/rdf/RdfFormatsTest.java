package com.ebremer.lws.server.rdf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFFormat;
import org.junit.jupiter.api.Test;

/**
 * {@link RdfFormats} — the media-type registry and {@code Accept} negotiation every read and every
 * write passes through, and one of the four classes the review found to have no test at all. That
 * absence is named as the reason finding M38 (TriG quad loss), the {@code text/n3} mis-alias and the
 * dead branches in {@code negotiate} all went unnoticed.
 *
 * <p>Three things are worth more than the rest here. {@link #onlyServerMintedVariantTokensAreRecognised()}
 * pins the authority {@code Etags.baseOf} consults before trimming an entity-tag, which is what stops
 * a client-invented tag containing a {@code .} from being trimmed into matching a real one (M21).
 * {@link #n3IsNotAnAliasForNTriples()} pins a deliberate <em>absence</em> from the table.
 * {@link #serverPreferenceBreaksAQualityTie()} pins that header order does not decide a tie, which is
 * the one thing a rewrite of the negotiation loop would silently invert.
 *
 * <p><strong>Three tests in the last section fail today.</strong> They assert the correct HTTP
 * behaviour for two still-open low findings rather than enshrining what the code does now; each says
 * what the fix is. See the section comment.
 *
 * @author Erich Bremer
 */
class RdfFormatsTest {

    private static String negotiated(String accept) {
        return RdfFormats.negotiate(accept).mediaType();
    }

    // ----- the table -----

    @Test
    void theServerDefaultIsTurtle() {
        assertEquals(RdfFormats.TURTLE, RdfFormats.DEFAULT.mediaType());
        assertEquals(Lang.TURTLE, RdfFormats.DEFAULT.lang());
        assertEquals(RDFFormat.TURTLE_PRETTY, RdfFormats.DEFAULT.writeFormat());
        assertEquals("ttl", RdfFormats.DEFAULT.variantToken());
    }

    /**
     * Five serializations of one graph must carry five different entity-tags (RFC 9110 &sect;8.8.1),
     * and {@code Etags.qualify} builds those tags out of these tokens. Two entries sharing a token is
     * finding M21 back again: a client that cached the Turtle would be answered {@code 304} for
     * JSON-LD.
     */
    @Test
    void eachSupportedSerializationCarriesItsOwnVariantToken() {
        List<String> tokens = List.of(RdfFormats.TURTLE, RdfFormats.JSONLD, RdfFormats.NTRIPLES,
                        RdfFormats.RDFXML, RdfFormats.TRIG).stream()
                .map(mt -> RdfFormats.negotiate(mt).variantToken())
                .toList();
        assertEquals(List.of("ttl", "jsonld", "nt", "rdfxml", "trig"), tokens);
        assertEquals(5, Set.copyOf(tokens).size(), "two representations sharing one tag is M21");
    }

    /**
     * {@code text/n3} is deliberately absent rather than aliased. It used to be wired to the
     * N-Triples parser, which is not an alias but a different language: N3 is a superset of Turtle,
     * so a genuine N3 document failed to parse while a document that happened to be N-Triples was
     * accepted under a media type this server does not implement. Absent from the table it is an
     * honest {@code 415}.
     */
    @Test
    void n3IsNotAnAliasForNTriples() {
        assertTrue(RdfFormats.langForContentType("text/n3").isEmpty());
        assertFalse(RdfFormats.isRdfContentType("text/n3"));
        assertTrue(RdfFormats.langForContentType("text/n3; charset=utf-8").isEmpty());
    }

    @Test
    void langForContentTypeIgnoresParametersAndCase() {
        assertEquals(Lang.TURTLE, RdfFormats.langForContentType("text/turtle").orElse(null));
        assertEquals(Lang.TURTLE, RdfFormats.langForContentType("text/turtle; charset=utf-8").orElse(null));
        assertEquals(Lang.TURTLE, RdfFormats.langForContentType("TEXT/TURTLE").orElse(null));
        assertEquals(Lang.TURTLE, RdfFormats.langForContentType("  text/turtle ; q=1 ").orElse(null));
        assertEquals(Lang.JSONLD, RdfFormats.langForContentType("application/ld+json").orElse(null));
        assertEquals(Lang.NTRIPLES, RdfFormats.langForContentType("application/n-triples").orElse(null));
        assertEquals(Lang.RDFXML, RdfFormats.langForContentType("application/rdf+xml").orElse(null));
        assertEquals(Lang.TRIG, RdfFormats.langForContentType("application/trig").orElse(null));

        assertTrue(RdfFormats.langForContentType(null).isEmpty(), "an absent Content-Type has no Lang");
        assertTrue(RdfFormats.langForContentType("application/json").isEmpty());
        assertTrue(RdfFormats.langForContentType("text/turtlex").isEmpty(),
                "the lookup is exact, not a prefix match");
    }

    @Test
    void isRdfContentTypeAcceptsExactlyTheTypesThatHaveALang() {
        for (String mt : List.of(RdfFormats.TURTLE, RdfFormats.JSONLD, RdfFormats.NTRIPLES,
                RdfFormats.RDFXML, RdfFormats.TRIG, "text/turtle; charset=utf-8", "APPLICATION/TRIG")) {
            assertTrue(RdfFormats.isRdfContentType(mt), mt);
        }
        for (String mt : List.of("text/n3", "application/json", "application/lws+json",
                "text/plain", "application/octet-stream", "application/xml")) {
            assertFalse(RdfFormats.isRdfContentType(mt), mt);
        }
        assertFalse(RdfFormats.isRdfContentType(null), "an absent Content-Type is not RDF");
    }

    @Test
    void isJsonRecognisesTheWholeSuffixFamily() {
        for (String mt : List.of("application/json", "application/lws+json", "application/ld+json",
                "application/merge-patch+json", "application/json-patch+json",
                "application/json; charset=utf-8", "APPLICATION/LWS+JSON")) {
            assertTrue(RdfFormats.isJson(mt), mt);
        }
        for (String mt : List.of("text/turtle", "application/xml", "application/jsonx", "text/plain")) {
            assertFalse(RdfFormats.isJson(mt), mt);
        }
        assertFalse(RdfFormats.isJson(null), "an absent Content-Type is not JSON");
    }

    @Test
    void stripParametersLowercasesAndTrims() {
        assertEquals("text/turtle", RdfFormats.stripParameters("  Text/Turtle ; charset=utf-8"));
        assertEquals("text/turtle", RdfFormats.stripParameters("text/turtle"));
        assertEquals("application/ld+json", RdfFormats.stripParameters("  APPLICATION/LD+JSON  "));
        assertEquals("text/turtle", RdfFormats.stripParameters("text/turtle;"),
                "an empty parameter section still leaves a bare media type");
    }

    // ----- negotiation -----

    @Test
    void negotiateFallsBackToTurtle() {
        assertEquals(RdfFormats.TURTLE, negotiated(null), "no Accept at all");
        assertEquals(RdfFormats.TURTLE, negotiated(""));
        assertEquals(RdfFormats.TURTLE, negotiated("   "));
        assertEquals(RdfFormats.TURTLE, negotiated("*/*"));
        assertEquals(RdfFormats.TURTLE, negotiated("text/*"));
        // A type this server does not serve: no entry matches by name and no wildcard is present,
        // so the documented fallback applies rather than a 406.
        assertEquals(RdfFormats.TURTLE, negotiated("image/png"));
        // Same outcome by the other route: the type half matches, so the wildcard branch answers.
        assertEquals(RdfFormats.TURTLE, negotiated("application/octet-stream"));
    }

    @Test
    void negotiatePicksTheHighestQuality() {
        assertEquals(RdfFormats.JSONLD, negotiated("text/turtle;q=0.5, application/ld+json;q=0.9"));
        assertEquals(RdfFormats.TURTLE, negotiated("text/turtle;q=0.9, application/ld+json;q=0.5"));
        assertEquals(RdfFormats.RDFXML, negotiated("application/rdf+xml"));
        assertEquals(RdfFormats.TRIG, negotiated("application/trig"));
        assertEquals(RdfFormats.NTRIPLES, negotiated("application/n-triples"));
        assertEquals(RdfFormats.NTRIPLES,
                negotiated("text/turtle;q=0.2, application/rdf+xml;q=0.3, application/n-triples;q=0.8"));
    }

    /**
     * Server preference, not header order, settles a tie. The list in {@code ENTRIES} is the
     * tie-break, so both orderings of the same two equal-quality types answer Turtle; a rewrite that
     * took the first matching header item instead would pass every other test in this file.
     */
    @Test
    void serverPreferenceBreaksAQualityTie() {
        assertEquals(RdfFormats.TURTLE, negotiated("application/ld+json, text/turtle"));
        assertEquals(RdfFormats.TURTLE, negotiated("text/turtle, application/ld+json"));
        assertEquals(RdfFormats.JSONLD, negotiated("application/trig, application/ld+json"),
                "with Turtle unasked-for, JSON-LD is the next server preference");
    }

    /** A malformed {@code q} is read as "no preference expressed", not as "unacceptable". */
    @Test
    void anUnparseableQualityIsTreatedAsOne() {
        assertEquals(RdfFormats.TURTLE, negotiated("text/turtle;q=abc"));
        assertEquals(RdfFormats.JSONLD, negotiated("application/ld+json;q=abc, text/turtle;q=0.5"));
    }

    /** A blank or empty element in the list is skipped rather than parsed into a wildcard. */
    @Test
    void anEmptyAcceptElementIsIgnored() {
        assertEquals(RdfFormats.JSONLD, negotiated("application/ld+json, , "));
    }

    /**
     * Parameter names are case-insensitive too (RFC 9110 §5.6.6), and only the media type was being
     * folded — so {@code Q=0} parsed as no parameter at all, the quality silently reverted to 1.0,
     * and the specificity fix above was defeated by one character. Measured before the fix:
     * {@code text/turtle;Q=0, application/ld+json;q=0.5} was answered with Turtle.
     */
    @Test
    void qualityIsRecognisedWhateverItsCase() {
        assertEquals(RdfFormats.JSONLD,
                RdfFormats.negotiate("text/turtle;Q=0, application/ld+json;q=0.5").mediaType());
        assertEquals(RdfFormats.JSONLD,
                RdfFormats.negotiate("text/turtle;Q=0.1, application/ld+json;Q=0.9").mediaType());
        assertEquals(RdfFormats.NTRIPLES,
                RdfFormats.negotiate("*/*;Q=0.9, application/n-triples;Q=1.0").mediaType());
    }

    @Test
    void aTypeExcludedWithQualityZeroIsNotChosenWhenAnotherTypeIsAcceptable() {
        assertEquals(RdfFormats.JSONLD, negotiated("application/ld+json, text/turtle;q=0"));
        assertEquals(RdfFormats.TRIG, negotiated("application/trig, application/ld+json;q=0"));
    }

    // ----- prefersRdf and the JSON family -----

    /**
     * A container is served as {@code application/lws+json} unless the client asked for a pure-RDF
     * type <em>more</em> strongly, because lws+json also satisfies {@code application/ld+json} and
     * {@code application/json}. The {@code *}/{@code *} case is the one that matters: a browser or a
     * plain {@code curl} gets the JSON representation.
     */
    @Test
    void prefersRdfOnlyOnAnExplicitHigherQualityRdfPreference() {
        assertFalse(RdfFormats.prefersRdf(null));
        assertFalse(RdfFormats.prefersRdf(""));
        assertFalse(RdfFormats.prefersRdf("*/*"), "a wildcard ties, and a tie is not a preference");
        assertFalse(RdfFormats.prefersRdf("application/ld+json"));
        assertFalse(RdfFormats.prefersRdf("application/lws+json"));
        assertFalse(RdfFormats.prefersRdf("application/json"));
        assertFalse(RdfFormats.prefersRdf("text/turtle;q=0.9, application/json"));

        assertTrue(RdfFormats.prefersRdf("text/turtle"));
        assertTrue(RdfFormats.prefersRdf("application/n-triples"));
        assertTrue(RdfFormats.prefersRdf("application/trig"));
        assertTrue(RdfFormats.prefersRdf("text/turtle, application/json;q=0.5"));
        assertTrue(RdfFormats.prefersRdf("text/turtle;q=0.5, application/lws+json;q=0.4"));
    }

    /**
     * The body is identical whichever of the three names comes back; echoing the one the client
     * actually asked for is what keeps a strict client from rejecting its own request's answer.
     */
    @Test
    void jsonFamilyContentTypeEchoesTheHighestQualityJsonType() {
        assertEquals("application/lws+json", RdfFormats.jsonFamilyContentType(null));
        assertEquals("application/lws+json", RdfFormats.jsonFamilyContentType(""));
        assertEquals("application/lws+json", RdfFormats.jsonFamilyContentType("*/*"),
                "lws+json is the canonical name and wins the wildcard");
        assertEquals("application/lws+json", RdfFormats.jsonFamilyContentType("text/turtle"),
                "no JSON type asked for at all still answers the canonical name");
        assertEquals("application/lws+json",
                RdfFormats.jsonFamilyContentType("application/json, application/lws+json"),
                "lws+json wins a tie");

        assertEquals("application/json", RdfFormats.jsonFamilyContentType("application/json"));
        assertEquals(RdfFormats.JSONLD, RdfFormats.jsonFamilyContentType("application/ld+json"));
        assertEquals("application/json",
                RdfFormats.jsonFamilyContentType("application/ld+json;q=0.5, application/json;q=0.9"));
        assertEquals(RdfFormats.JSONLD,
                RdfFormats.jsonFamilyContentType("application/lws+json;q=0.1, application/ld+json;q=0.2"));
    }

    // ----- variant tokens -----

    /**
     * {@code Etags.baseOf} strips a suffix only when this says the suffix is one the server minted.
     * That membership test is the whole defence: without it, a client-invented {@code If-Match} tag
     * that happens to contain a {@code .} could be trimmed into matching a real state tag. So the
     * comparison must stay exact — no case folding, no trimming, no prefix match.
     */
    @Test
    void onlyServerMintedVariantTokensAreRecognised() {
        for (String token : List.of("ttl", "jsonld", "nt", "rdfxml", "trig", RdfFormats.LWS_JSON_VARIANT)) {
            assertTrue(RdfFormats.isVariantToken(token), token);
        }
        assertEquals("lwsjson", RdfFormats.LWS_JSON_VARIANT);

        for (String token : List.of("TTL", "Ttl", "", " ", "nt ", " nt", "evil", "n", "ttl2", "ttl.")) {
            assertFalse(RdfFormats.isVariantToken(token), "wrongly accepted as a variant token: " + token);
        }
    }

    /**
     * {@code Etags.qualify} joins the state tag to the variant with a {@code .} and
     * {@code Etags.baseOf} splits on the last one, so a token carrying a {@code .} of its own would
     * make that split ambiguous and silently corrupt conditional writes.
     */
    @Test
    void noVariantTokenContainsTheEtagSeparator() {
        for (String token : List.of("ttl", "jsonld", "nt", "rdfxml", "trig", RdfFormats.LWS_JSON_VARIANT)) {
            assertFalse(token.contains("."), token);
            assertFalse(token.isBlank(), token);
        }
    }

    // ------------------------------------------------------------------------------------------
    // Two still-open low findings. The three tests below assert the CORRECT behaviour and
    // therefore FAIL against the current code; they are deliberately not written the other way
    // round, because a test that enshrines the defect makes the defect permanent.
    // ------------------------------------------------------------------------------------------

    /**
     * RFC 9110 &sect;12.5.1: a media range that matches more precisely takes precedence, so
     * {@code application/ld+json;q=0.1} overrides the {@code application/*;q=0.9} that also covers it.
     * N-Triples, RDF/XML and TriG keep 0.9 and Turtle is not covered at all, so the server preference
     * among the 0.9 group answers N-Triples.
     *
     * <p><strong>Fails today.</strong> {@code matchQuality} takes the <em>maximum</em> q over every
     * matching range instead of the q of the most specific one, so JSON-LD is scored 0.9 and wins.
     * The fix is to rank candidate ranges by specificity (exact type and subtype, then
     * {@code type}/{@code *}, then {@code *}/{@code *}) and take the q of the best-ranked match
     * rather than the largest.
     */
    @Test
    void aMoreSpecificMediaRangeOverridesABroaderOne() {
        assertEquals(RdfFormats.NTRIPLES, negotiated("application/*;q=0.9, application/ld+json;q=0.1"));
    }

    /**
     * {@code q=0} on a specific type means "not acceptable" and must beat a broader range that would
     * otherwise cover it, so a client saying "anything but Turtle" gets JSON-LD.
     *
     * <p><strong>Fails today.</strong> The same maximum-over-ranges rule scores Turtle 0.9 from the
     * wildcard and never sees the explicit rejection; the server answers Turtle, exactly the
     * representation the client refused. Falls out of the specificity fix above, because the most
     * specific match is then the {@code q=0} one and {@code negotiate} already skips {@code q <= 0}.
     */
    @Test
    void anExplicitQualityOfZeroRejectsThatTypeDespiteABroaderWildcard() {
        assertEquals(RdfFormats.JSONLD, negotiated("*/*;q=0.9, text/turtle;q=0"));
    }

    /**
     * Media types are ASCII tokens (RFC 9110 &sect;8.3.1) and are never locale text, so folding one
     * to lower case must not consult the JVM's default locale.
     *
     * <p><strong>Fails today.</strong> {@code stripParameters} and {@code parseAccept} both call the
     * no-argument {@code String.toLowerCase()}. On a Turkish-locale JVM {@code "APPLICATION/N-TRIPLES"}
     * folds to {@code "applıcatıon/n-trıples"} with dotless i, which matches nothing in the table: a
     * client that uppercases its headers is answered {@code 415} for a body this server does support,
     * and Turtle for an {@code Accept} that named N-Triples. The fix is
     * {@code toLowerCase(Locale.ROOT)} at both call sites.
     *
     * <p>The default locale is process-wide state; this suite declares no parallel execution, and the
     * original is restored in a {@code finally} either way.
     */
    @Test
    void mediaTypeFoldingIsIndependentOfTheJvmDefaultLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr"));
            assertEquals("application/n-triples", RdfFormats.stripParameters("APPLICATION/N-TRIPLES"));
            assertEquals(Lang.NTRIPLES,
                    RdfFormats.langForContentType("APPLICATION/N-TRIPLES; charset=utf-8").orElse(null));
            assertEquals(RdfFormats.NTRIPLES, negotiated("APPLICATION/N-TRIPLES"));
        } finally {
            Locale.setDefault(original);
        }
    }
}
