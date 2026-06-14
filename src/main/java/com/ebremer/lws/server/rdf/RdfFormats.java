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

    /** One supported RDF serialization. */
    public record Entry(String mediaType, Lang lang, RDFFormat writeFormat) {
    }

    public static final String TURTLE = "text/turtle";
    public static final String JSONLD = "application/ld+json";
    public static final String NTRIPLES = "application/n-triples";
    public static final String RDFXML = "application/rdf+xml";
    public static final String TRIG = "application/trig";

    /** Ordered by server preference (first = most preferred when a client expresses no preference). */
    private static final List<Entry> ENTRIES = List.of(
            new Entry(TURTLE, Lang.TURTLE, RDFFormat.TURTLE_PRETTY),
            new Entry(JSONLD, Lang.JSONLD, RDFFormat.JSONLD),
            new Entry(NTRIPLES, Lang.NTRIPLES, RDFFormat.NTRIPLES),
            new Entry(RDFXML, Lang.RDFXML, RDFFormat.RDFXML_PRETTY),
            new Entry(TRIG, Lang.TRIG, RDFFormat.TRIG_PRETTY));

    private static final Map<String, Entry> BY_MEDIA_TYPE = new LinkedHashMap<>();

    static {
        for (Entry e : ENTRIES) {
            BY_MEDIA_TYPE.put(e.mediaType(), e);
        }
        // common aliases
        BY_MEDIA_TYPE.put("text/n3", new Entry(NTRIPLES, Lang.NTRIPLES, RDFFormat.NTRIPLES));
        BY_MEDIA_TYPE.put("application/n-triples", new Entry(NTRIPLES, Lang.NTRIPLES, RDFFormat.NTRIPLES));
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
        return (semi < 0 ? mediaType : mediaType.substring(0, semi)).trim().toLowerCase();
    }

    private static double matchQuality(String mediaType, List<AcceptItem> items) {
        String[] parts = mediaType.split("/", 2);
        String type = parts[0];
        String sub = parts.length > 1 ? parts[1] : "*";
        double q = 0.0;
        for (AcceptItem it : items) {
            boolean typeOk = it.type.equals("*") || it.type.equals(type);
            boolean subOk = it.subtype.equals("*") || it.subtype.equals(sub);
            if (typeOk && subOk && it.q > q) {
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
            String mt = segs[0].trim().toLowerCase();
            double q = 1.0;
            for (int i = 1; i < segs.length; i++) {
                String s = segs[i].trim();
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
