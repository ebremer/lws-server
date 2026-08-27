package com.ebremer.lws.server.rdf;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFFormat;

/**
 * RDF media-type registry and HTTP content negotiation for LWS RDF representations.
 *
 * <p>The LWS core draft does not yet pin a concrete serialization set, so we support the
 * conventional Linked Data set: Turtle (default), JSON-LD, N-Triples and RDF/XML.
 *
 * @author Erich Bremer
 */
public final class RdfFormats {

    private RdfFormats() {
    }

    /**
     * One supported RDF serialization.
     *
     * @param variantToken a short, stable token naming this serialization inside an entity-tag, so
     *                     that one resource's five representations carry five different tags
     *                     (RFC 9110 &sect;8.8.1, finding M21). It is opaque to clients and must stay
     *                     free of the {@code .} that separates it from the state tag; see
     *                     {@code Etags.qualify}.
     */
    public record Entry(String mediaType, Lang lang, RDFFormat writeFormat, String variantToken) {
    }

    public static final String TURTLE = "text/turtle";
    public static final String JSONLD = "application/ld+json";
    public static final String NTRIPLES = "application/n-triples";
    public static final String RDFXML = "application/rdf+xml";
    public static final String TRIG = "application/trig";

    /** The variant token for the {@code application/lws+json} rendering, which is not RDF. */
    public static final String LWS_JSON_VARIANT = "lwsjson";

    /** Ordered by server preference (first = most preferred when a client expresses no preference). */
    private static final List<Entry> ENTRIES = List.of(
            new Entry(TURTLE, Lang.TURTLE, RDFFormat.TURTLE_PRETTY, "ttl"),
            new Entry(JSONLD, Lang.JSONLD, RDFFormat.JSONLD, "jsonld"),
            new Entry(NTRIPLES, Lang.NTRIPLES, RDFFormat.NTRIPLES, "nt"),
            new Entry(RDFXML, Lang.RDFXML, RDFFormat.RDFXML_PRETTY, "rdfxml"),
            new Entry(TRIG, Lang.TRIG, RDFFormat.TRIG_PRETTY, "trig"));

    private static final Map<String, Entry> BY_MEDIA_TYPE = new LinkedHashMap<>();

    /** Every token {@code Etags.baseOf} will strip; nothing else is treated as a variant. */
    private static final java.util.Set<String> VARIANT_TOKENS;

    static {
        for (Entry e : ENTRIES) {
            BY_MEDIA_TYPE.put(e.mediaType(), e);
        }
        // common aliases
        // `text/n3` is deliberately NOT registered. It was mapped to the N-Triples parser, which is
        // not an alias but a different language: N3 is a superset of Turtle, so a genuine N3 document
        // fails to parse and a document that happens to be N-Triples is accepted under a media type
        // this server does not implement. Absent from the table, `text/n3` is an honest 415.
        BY_MEDIA_TYPE.put("application/n-triples",
                new Entry(NTRIPLES, Lang.NTRIPLES, RDFFormat.NTRIPLES, "nt"));

        java.util.Set<String> tokens = new java.util.LinkedHashSet<>();
        ENTRIES.forEach(e -> tokens.add(e.variantToken()));
        tokens.add(LWS_JSON_VARIANT);
        VARIANT_TOKENS = java.util.Set.copyOf(tokens);
    }

    /**
     * Whether {@code token} is one this server appends to an entity-tag to name a representation.
     *
     * <p>The membership test is what keeps tag comparison honest: only a token minted here is
     * stripped back off, so a client-invented tag that happens to contain a {@code .} cannot be
     * trimmed into matching a real one.
     */
    public static boolean isVariantToken(String token) {
        return VARIANT_TOKENS.contains(token);
    }

    public static final Entry DEFAULT = ENTRIES.get(0);

    /** Resolve the Jena {@link Lang} for a request Content-Type, if it is a supported RDF type. */
    public static Optional<Lang> langForContentType(String contentType) {
        if (contentType == null) {
            return Optional.empty();
        }
        String mt = stripParameters(contentType);
        Entry e = BY_MEDIA_TYPE.get(mt);
        return e == null ? Optional.empty() : Optional.of(e.lang());
    }

    public static boolean isRdfContentType(String contentType) {
        return langForContentType(contentType).isPresent();
    }

    /** True if the media type is JSON ({@code application/json} or a {@code +json} suffix type). */
    public static boolean isJson(String contentType) {
        if (contentType == null) {
            return false;
        }
        String mt = stripParameters(contentType);
        return mt.equals("application/json") || mt.endsWith("+json");
    }

    /**
     * Choose the best RDF serialization for an HTTP {@code Accept} header.
     * Falls back to the server default (Turtle) when the header is absent or matches no
     * supported type (including {@code *}/{@code *}).
     */
    public static Entry negotiate(String acceptHeader) {
        if (acceptHeader == null || acceptHeader.isBlank()) {
            return DEFAULT;
        }
        List<AcceptItem> items = parseAccept(acceptHeader);
        Entry best = null;
        double bestQ = -1.0;
        int bestRank = Integer.MAX_VALUE;
        for (int rank = 0; rank < ENTRIES.size(); rank++) {
            Entry e = ENTRIES.get(rank);
            double q = matchQuality(e.mediaType(), items);
            if (q <= 0.0) {
                continue;
            }
            if (q > bestQ || (q == bestQ && rank < bestRank)) {
                best = e;
                bestQ = q;
                bestRank = rank;
            }
        }
        // If the client sent */* (or text/*) but nothing matched by name, honour the wildcard.
        if (best == null) {
            for (AcceptItem it : items) {
                if (it.type.equals("*") || it.type.equals("application") || it.type.equals("text")) {
                    return DEFAULT;
                }
            }
        }
        return best == null ? DEFAULT : best;
    }

    /**
     * For a container read, decide whether the client prefers an RDF serialization over the JSON
     * family. The LWS container representation ({@code application/lws+json}) also satisfies
     * {@code application/ld+json} and {@code application/json}; only an explicit, higher-quality
     * preference for a pure-RDF type (Turtle/N-Triples/RDF-XML/TriG) selects RDF. Absent/wildcard
     * Accept yields the JSON representation.
     */
    public static boolean prefersRdf(String acceptHeader) {
        if (acceptHeader == null || acceptHeader.isBlank()) {
            return false;
        }
        List<AcceptItem> items = parseAccept(acceptHeader);
        double json = Math.max(matchQuality("application/lws+json", items),
                Math.max(matchQuality(JSONLD, items), matchQuality("application/json", items)));
        double rdf = Math.max(matchQuality(TURTLE, items),
                Math.max(matchQuality(NTRIPLES, items),
                        Math.max(matchQuality(RDFXML, items), matchQuality(TRIG, items))));
        return rdf > json;
    }

    /**
     * Pick the JSON-family media type to echo in {@code Content-Type} for an lws+json response: the
     * highest-quality of {@code application/lws+json} / {@code application/ld+json} /
     * {@code application/json} requested (lws+json wins ties and the wildcard/absent case, as the
     * canonical type). The response body is identical regardless (lws10-core lws-media-type).
     */
    public static String jsonFamilyContentType(String acceptHeader) {
        if (acceptHeader == null || acceptHeader.isBlank()) {
            return "application/lws+json";
        }
        List<AcceptItem> items = parseAccept(acceptHeader);
        double lws = matchQuality("application/lws+json", items);
        double ld = matchQuality(JSONLD, items);
        double json = matchQuality("application/json", items);
        double max = Math.max(lws, Math.max(ld, json));
        if (max <= 0 || lws == max) {
            return "application/lws+json";
        }
        return ld == max ? JSONLD : "application/json";
    }

    public static String stripParameters(String mediaType) {
        int semi = mediaType.indexOf(';');
        // Locale.ROOT: a media type is a protocol token, not display text. The default locale
        // folds "I" to a dotless "\u0131" on a Turkish-locale JVM, so "APPLICATION/N-TRIPLES"
        // became "applicatio\u0131..." and matched nothing — a supported body answered 415 on one
        // machine and 200 on another.
        return (semi < 0 ? mediaType : mediaType.substring(0, semi)).trim()
                .toLowerCase(java.util.Locale.ROOT);
    }

    /**
     * The quality this client assigned to {@code mediaType}.
     *
     * <p>From the <em>most specific</em> media range that matches, not from the highest-quality one.
     * RFC 9110 §12.5.1 is explicit about this — {@code text/html;q=0.7, text/*;q=0.3} means 0.7 for
     * {@code text/html} — and taking the maximum instead got two things wrong at once. A client
     * saying {@code application/*;q=0.9, application/ld+json;q=0.1} was served JSON-LD, the one
     * application type it least wanted; and, worse, a client saying
     * <code>*&#47;*;q=0.9, text/turtle;q=0</code> was served Turtle, because the wildcard's 0.9 beat the
     * explicit zero. A {@code q=0} is a <em>refusal</em> (§12.4.2), so that was the server answering
     * with the single representation the client had said it would not accept.
     *
     * <p>Specificity ranks as the grammar does: an exact {@code type/subtype} beats {@code type/*},
     * which beats <code>*&#47;*</code>. Among ranges of equal specificity the highest quality wins,
     * which is what makes a repeated type harmless.
     */
    private static double matchQuality(String mediaType, List<AcceptItem> items) {
        String[] parts = mediaType.split("/", 2);
        String type = parts[0];
        String sub = parts.length > 1 ? parts[1] : "*";
        int bestSpecificity = -1;
        double q = 0.0;
        for (AcceptItem it : items) {
            boolean typeOk = it.type.equals("*") || it.type.equals(type);
            boolean subOk = it.subtype.equals("*") || it.subtype.equals(sub);
            if (!typeOk || !subOk) {
                continue;
            }
            int specificity = it.type.equals("*") ? 0 : (it.subtype.equals("*") ? 1 : 2);
            if (specificity > bestSpecificity || (specificity == bestSpecificity && it.q > q)) {
                bestSpecificity = specificity;
                q = it.q;
            }
        }
        return q;
    }

    private record AcceptItem(String type, String subtype, double q) {
    }

    private static List<AcceptItem> parseAccept(String header) {
        List<AcceptItem> out = new ArrayList<>();
        for (String token : header.split(",")) {
            String t = token.trim();
            if (t.isEmpty()) {
                continue;
            }
            String[] segs = t.split(";");
            String mt = segs[0].trim().toLowerCase(java.util.Locale.ROOT); // see stripParameters
            double q = 1.0;
            for (int i = 1; i < segs.length; i++) {
                // Parameter NAMES are case-insensitive too (RFC 9110 5.6.6), and only the media
                // type was being folded. So `Q=0` parsed as no parameter at all and the quality
                // silently reverted to 1.0 -- which meant a client writing `text/turtle;Q=0` was
                // served Turtle, the one representation it had just refused. That is the same
                // defect the specificity fix above exists to close, defeated by one character.
                String s = segs[i].trim().toLowerCase(java.util.Locale.ROOT);
                if (s.startsWith("q=")) {
                    try {
                        q = Double.parseDouble(s.substring(2).trim());
                    } catch (NumberFormatException ignored) {
                        q = 1.0;
                    }
                }
            }
            String[] mtParts = mt.split("/", 2);
            String type = mtParts[0].isEmpty() ? "*" : mtParts[0];
            String sub = mtParts.length > 1 && !mtParts[1].isEmpty() ? mtParts[1] : "*";
            out.add(new AcceptItem(type, sub, q));
        }
        return out;
    }
}
