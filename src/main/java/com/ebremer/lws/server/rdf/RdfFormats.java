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
 * <p>Two kinds of negotiation live here. {@link #negotiate}, {@link #quality},
 * {@link #prefersRdf} and {@link #jsonFamilyContentType} choose among representations that name no
 * profile: an RDF data resource, an ACL, the storage description, a subscription, a search result.
 * {@link #negotiateContainer} chooses a <em>container</em> representation, every one of which this
 * server produces in the LWS profile (lws10-core, LWS Profile and Content Negotiation), so it also
 * honours an {@code Accept} media range that asks for that profile, and says which variant it chose
 * so the response can name the profile when it was asked for.
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
    /**
     * N-Quads, offered for container representations only (see {@link #negotiateContainer}). It is
     * deliberately not in the table data resources are read and written through: accepting it for
     * writes would turn an N-Quads upload that is stored as opaque bytes today into an RDF source,
     * and refuse one that carries named graphs, which is not a change to make on the side.
     */
    public static final String NQUADS = "application/n-quads";

    /**
     * The URI that identifies the LWS profile (lws10-core, LWS Profile; RFC 6906). A client asks for
     * a container representation in it with the {@code profile} parameter of an RDF media type, and
     * the response names it the same way.
     */
    public static final String LWS_PROFILE = "https://www.w3.org/ns/lws/v1";

    /** The variant token for the {@code application/lws+json} rendering, which is not RDF. */
    public static final String LWS_JSON_VARIANT = "lwsjson";

    /** The container representation's media type (lws10-core, LWS Media Type). */
    public static final String LWS_JSON = "application/lws+json";

    /**
     * The storage description's media type: a controlled identifier document extended with the LWS
     * vocabulary (lws10-core, LWS Media Type).
     */
    public static final String LWS_CID = "application/lws+cid";

    /** The variant token for the {@code application/lws+cid} rendering of the storage description. */
    public static final String LWS_CID_VARIANT = "lwscid";

    /** Ordered by server preference (first = most preferred when a client expresses no preference). */
    private static final List<Entry> ENTRIES = List.of(
            new Entry(TURTLE, Lang.TURTLE, RDFFormat.TURTLE_PRETTY, "ttl"),
            new Entry(JSONLD, Lang.JSONLD, RDFFormat.JSONLD, "jsonld"),
            new Entry(NTRIPLES, Lang.NTRIPLES, RDFFormat.NTRIPLES, "nt"),
            new Entry(RDFXML, Lang.RDFXML, RDFFormat.RDFXML_PRETTY, "rdfxml"),
            new Entry(TRIG, Lang.TRIG, RDFFormat.TRIG_PRETTY, "trig"));

    /** N-Quads, for container output only; a container's RDF is one graph, written as the default graph. */
    private static final Entry NQUADS_ENTRY = new Entry(NQUADS, Lang.NQUADS, RDFFormat.NQUADS, "nq");

    /**
     * The RDF serializations a container is offered in, by server preference. JSON-LD is not among
     * them: a container's {@code application/ld+json} representation is the lws+json document
     * itself, which is RDF by construction, so it is chosen with the JSON family rather than
     * written out of a model.
     */
    private static final List<Entry> CONTAINER_RDF = List.of(ENTRIES.get(0), ENTRIES.get(2), ENTRIES.get(3),
            ENTRIES.get(4), NQUADS_ENTRY);

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
        tokens.add(NQUADS_ENTRY.variantToken());
        tokens.add(LWS_JSON_VARIANT);
        tokens.add(LWS_CID_VARIANT);
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
     *
     * <p>The representations chosen here — an RDF data resource, an ACL, the storage description —
     * are in no profile, so a media range carrying a {@code profile} parameter does not match: the
     * LWS profile is defined for container representations, which {@link #negotiateContainer}
     * chooses, and this server produces no other profile.
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
     * For a JSON document that also has an RDF rendering — a subscription — decide whether the
     * client prefers an RDF serialization over the JSON family. The document also satisfies
     * {@code application/ld+json} and {@code application/json}; only an explicit, higher-quality
     * preference for a pure-RDF type (Turtle/N-Triples/RDF-XML/TriG) selects RDF. Absent/wildcard
     * Accept yields the JSON representation.
     *
     * <p>Neither rendering is in a profile, so a media range carrying a {@code profile} parameter
     * counts for neither. A container is negotiated by {@link #negotiateContainer} instead.
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
     * The quality {@code acceptHeader} gives {@code mediaType}: {@code 1.0} when there is no
     * {@code Accept} at all, {@code 0.0} when it is refused or matched by nothing.
     *
     * <p>The quality of a representation that names no profile, so a media range carrying a
     * {@code profile} parameter does not count (see {@link #negotiate}).
     */
    public static double quality(String mediaType, String acceptHeader) {
        if (acceptHeader == null || acceptHeader.isBlank()) {
            return 1.0;
        }
        return matchQuality(stripParameters(mediaType), parseAccept(acceptHeader));
    }

    /**
     * Whether a request for the storage URI is asking for the storage description rather than the
     * root container listing.
     *
     * <p>This server's storage URI is its root container's URI, which lws10-core allows ("Storage
     * MAY function as a root container"), so one URI has two representations and {@code Accept}
     * decides between them. The core requires the storage URI to answer with the
     * {@code application/lws+cid} description "unless content negotiation requires a different
     * format", so the description wins whenever the client does not rank a container representation
     * — the lws+json family or an RDF serialization — strictly higher: no {@code Accept}, a bare
     * wildcard, and a browser's {@code *}{@code /*;q=0.8} all get the description, while
     * {@code Accept: application/lws+json} or {@code text/turtle} gets the container.
     *
     * <p>A container representation is ranked as {@link #negotiateContainer} ranks it, so a media
     * range asking for the LWS profile — {@code text/turtle;profile="https://www.w3.org/ns/lws/v1"},
     * {@code application/ld+json} with the same parameter — counts for the container. The profile is
     * defined for container representations only, so a client that names it is asking for the
     * container, not for the description.
     */
    public static boolean prefersStorageDescription(String acceptHeader) {
        if (acceptHeader == null || acceptHeader.isBlank()) {
            return true;
        }
        List<AcceptItem> items = parseAccept(acceptHeader);
        double cid = matchQuality(LWS_CID, items);
        if (cid <= 0.0) {
            return false;
        }
        double container = 0.0;
        for (String type : List.of(LWS_JSON, JSONLD, "application/json")) {
            container = Math.max(container, containerOffer(type, items).q());
        }
        for (Entry e : CONTAINER_RDF) {
            container = Math.max(container, containerOffer(e.mediaType(), items).q());
        }
        return cid >= container;
    }

    /**
     * Pick the JSON-family media type to echo in {@code Content-Type} for an LWS JSON document that
     * is not a container representation (a subscription, a search result): the highest-quality of
     * {@code application/lws+json} / {@code application/ld+json} / {@code application/json}
     * requested (lws+json wins ties and the wildcard/absent case, as the canonical type). The
     * response body is identical regardless.
     *
     * <p>A media range carrying a {@code profile} parameter does not count: these documents are not
     * in the LWS profile, which is defined for container representations, so
     * {@code application/ld+json;profile="https://www.w3.org/ns/lws/v1"} does not select
     * {@code application/ld+json} here (lws10-core: a server "MUST NOT select such a media type if it
     * cannot produce a representation in the LWS profile in it"). A container is negotiated by
     * {@link #negotiateContainer}.
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

    // ----- containers: the LWS profile -----

    /**
     * The representation of a container a client's {@code Accept} selected.
     *
     * @param mediaType the selected media type, without parameters
     * @param rdf       the RDF serialization to write the container's RDF in, or {@code null} for
     *                  the lws+json document itself (sent as {@code application/lws+json},
     *                  {@code application/ld+json} or {@code application/json})
     * @param profile   whether the response names the LWS profile in its {@code Content-Type},
     *                  which it does exactly when the media range that selected it asked for the
     *                  profile and the media type is an RDF one
     */
    public record ContainerVariant(String mediaType, Entry rdf, boolean profile) {

        /** Whether the container's RDF is written out in {@link #rdf}, rather than its JSON sent. */
        public boolean isRdf() {
            return rdf != null;
        }

        /**
         * The {@code Content-Type} to answer with, without a charset: the media type, and the
         * profile parameter when the client asked for the profile. Only the LWS profile URI is
         * named, even when the client listed others beside it, because it is the only one this
         * representation is in.
         */
        public String contentType() {
            return profile ? mediaType + ";profile=\"" + LWS_PROFILE + "\"" : mediaType;
        }

        /**
         * The token naming this representation inside an entity-tag ({@code Etags.qualify}). The
         * three JSON media types share one, as they always have: the bytes are the same document.
         * A serialization's token does not depend on {@link #profile} for the same reason — the
         * profile is what every container representation here is in, and naming it changes the
         * {@code Content-Type}, not the bytes.
         */
        public String variantToken() {
            return rdf == null ? LWS_JSON_VARIANT : rdf.variantToken();
        }
    }

    /** The canonical container representation, and the answer when nothing in {@code Accept} matches. */
    private static final ContainerVariant LWS_JSON_CONTAINER = new ContainerVariant(LWS_JSON, null, false);

    /**
     * Choose the representation of a container for an {@code Accept} header (lws10-core, Content
     * Negotiation).
     *
     * <p>Every container representation this server produces is in the LWS profile: the RDF ones are
     * derived from the {@code application/lws+json} document by reading it as JSON-LD, so they are
     * RDF isomorphic to it by construction, and the JSON ones are that document. So a media range is
     * honoured whether it asks for the profile ({@code text/turtle;profile="https://www.w3.org/ns/lws/v1"})
     * or not ({@code text/turtle}); a range naming only some <em>other</em> profile matches nothing,
     * because this server cannot produce that profile. Where both kinds of range cover a media type,
     * the more specific one decides, a range with a profile parameter being more specific than the
     * same range without one (RFC 9110 &sect;12.5.1).
     *
     * <p>Between the JSON family and RDF the choice stays quality-driven, as it has been: RDF only
     * when an RDF serialization is ranked strictly above every JSON form, so an absent {@code Accept}
     * or a wildcard gets {@code application/lws+json}, which also wins a tie inside the family.
     * Among the RDF serializations the server's order (Turtle, N-Triples, RDF/XML, TriG, N-Quads)
     * breaks a tie. When nothing matches, the answer is {@code application/lws+json}, the one
     * representation lws10-core requires — the fallback this server has always had, rather than a
     * {@code 406}.
     *
     * <p>The profile is named in the response only for an RDF media type ({@code application/ld+json}
     * and the serializations above): {@code application/lws+json} is the profile's own form and
     * {@code application/json} defines no parameters, so a range asking for the profile on either
     * matches it but the {@code Content-Type} stays bare.
     */
    public static ContainerVariant negotiateContainer(String acceptHeader) {
        if (acceptHeader == null || acceptHeader.isBlank()) {
            return LWS_JSON_CONTAINER;
        }
        List<AcceptItem> items = parseAccept(acceptHeader);
        double lws = containerOffer(LWS_JSON, items).q();
        Offer ld = containerOffer(JSONLD, items);
        double json = Math.max(lws, Math.max(ld.q(), containerOffer("application/json", items).q()));

        Entry bestRdf = null;
        Offer bestRdfOffer = null;
        for (Entry e : CONTAINER_RDF) {
            Offer o = containerOffer(e.mediaType(), items);
            if (o.q() > 0.0 && (bestRdfOffer == null || o.q() > bestRdfOffer.q())) {
                bestRdf = e;
                bestRdfOffer = o;
            }
        }
        if (bestRdfOffer != null && bestRdfOffer.q() > json) {
            return new ContainerVariant(bestRdf.mediaType(), bestRdf, bestRdfOffer.profile());
        }
        if (json <= 0.0 || lws == json) {
            return LWS_JSON_CONTAINER;
        }
        if (ld.q() == json) {
            return new ContainerVariant(JSONLD, null, ld.profile());
        }
        return new ContainerVariant("application/json", null, false);
    }

    /** How a client ranks one container media type, and whether the range that ranked it asked for the LWS profile. */
    private record Offer(double q, boolean profile) {
    }

    /**
     * The quality a client gives a container representation in {@code mediaType}, which this server
     * always produces in the LWS profile. Both readings of the media type are scored — as the profile
     * variant, which a range naming the LWS profile also matches, and as the plain one — and the
     * better wins; the profile is reported only when a range asking for it did, so a client that
     * asked for plain Turtle is answered with plain {@code text/turtle}. A range that refuses the
     * profile ({@code q=0}) but is outranked by a plain range for the same type still gets the
     * plain answer: the bytes are the same either way.
     */
    private static Offer containerOffer(String mediaType, List<AcceptItem> items) {
        Quality plain = matchQuality(mediaType, items, false);
        Quality inProfile = matchQuality(mediaType, items, true);
        if (inProfile.viaProfile() && inProfile.q() >= plain.q()) {
            return new Offer(inProfile.q(), inProfile.q() > 0.0);
        }
        return new Offer(Math.max(plain.q(), inProfile.q()), false);
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
     * The quality this client assigned to {@code mediaType}, a representation in no profile.
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
        return matchQuality(mediaType, items, false).q();
    }

    /** A client's quality for one representation, and whether a range carrying a profile decided it. */
    private record Quality(double q, boolean viaProfile) {
    }

    /**
     * The quality this client assigned to {@code mediaType}, from the most specific matching media
     * range (see {@link #matchQuality(String, List)}), for a representation that is in the LWS profile
     * ({@code inLwsProfile}) or in none.
     *
     * <p>A media range with a {@code profile} parameter matches only a representation in one of the
     * profiles it lists (RFC 6906; a range's parameters narrow it, RFC 9110 &sect;12.5.1), so it never
     * matches a representation in no profile, and matches one in the LWS profile only when the LWS
     * profile URI is among its values. It is more specific than the same range without the
     * parameter, and less specific than a narrower range: {@code text/turtle;profile=...} beats
     * {@code text/turtle}, which beats {@code text/*;profile=...}.
     */
    private static Quality matchQuality(String mediaType, List<AcceptItem> items, boolean inLwsProfile) {
        String[] parts = mediaType.split("/", 2);
        String type = parts[0];
        String sub = parts.length > 1 ? parts[1] : "*";
        int bestSpecificity = -1;
        double q = 0.0;
        boolean viaProfile = false;
        for (AcceptItem it : items) {
            boolean typeOk = it.type.equals("*") || it.type.equals(type);
            boolean subOk = it.subtype.equals("*") || it.subtype.equals(sub);
            if (!typeOk || !subOk) {
                continue;
            }
            if (it.profiles != null && !(inLwsProfile && it.profiles.contains(LWS_PROFILE))) {
                continue;
            }
            int range = it.type.equals("*") ? 0 : (it.subtype.equals("*") ? 1 : 2);
            int specificity = 2 * range + (it.profiles != null ? 1 : 0);
            if (specificity > bestSpecificity || (specificity == bestSpecificity && it.q > q)) {
                bestSpecificity = specificity;
                q = it.q;
                viaProfile = it.profiles != null;
            }
        }
        return new Quality(q, viaProfile);
    }

    /**
     * One media range of an {@code Accept} header.
     *
     * @param profiles the URIs its {@code profile} parameter lists, or {@code null} when it has no
     *                 such parameter (an empty set is a parameter that names nothing)
     */
    private record AcceptItem(String type, String subtype, double q, java.util.Set<String> profiles) {
    }

    private static List<AcceptItem> parseAccept(String header) {
        List<AcceptItem> out = new ArrayList<>();
        // Split outside quoted strings: a profile is a URI, and a quoted URI may hold the "," and
        // ";" that separate media ranges and parameters.
        for (String token : splitOutsideQuotes(header, ',')) {
            String t = token.trim();
            if (t.isEmpty()) {
                continue;
            }
            List<String> segs = splitOutsideQuotes(t, ';');
            String mt = segs.get(0).trim().toLowerCase(java.util.Locale.ROOT); // see stripParameters
            double q = 1.0;
            java.util.Set<String> profiles = null;
            for (int i = 1; i < segs.size(); i++) {
                String s = segs.get(i).trim();
                int eq = s.indexOf('=');
                if (eq < 0) {
                    continue;
                }
                // Parameter NAMES are case-insensitive too (RFC 9110 5.6.6), and only the media
                // type was being folded. So `Q=0` parsed as no parameter at all and the quality
                // silently reverted to 1.0 -- which meant a client writing `text/turtle;Q=0` was
                // served Turtle, the one representation it had just refused. That is the same
                // defect the specificity fix above exists to close, defeated by one character.
                // Values are NOT folded: a profile is a URI, and URIs compare case-sensitively.
                String name = s.substring(0, eq).trim().toLowerCase(java.util.Locale.ROOT);
                String value = s.substring(eq + 1).trim();
                if (name.equals("q")) {
                    try {
                        q = Double.parseDouble(value);
                    } catch (NumberFormatException ignored) {
                        q = 1.0;
                    }
                } else if (name.equals("profile")) {
                    // RFC 6906: a whitespace-separated list of URIs, quoted when it is more than
                    // one; accepted unquoted too, since a lone URI is commonly sent that way. A
                    // repeated parameter adds to the list rather than replacing it.
                    if (profiles == null) {
                        profiles = new java.util.LinkedHashSet<>();
                    }
                    for (String uri : unquote(value).split("\\s+")) {
                        if (!uri.isEmpty()) {
                            profiles.add(uri);
                        }
                    }
                }
            }
            String[] mtParts = mt.split("/", 2);
            String type = mtParts[0].isEmpty() ? "*" : mtParts[0];
            String sub = mtParts.length > 1 && !mtParts[1].isEmpty() ? mtParts[1] : "*";
            out.add(new AcceptItem(type, sub, q, profiles));
        }
        return out;
    }

    /** Split {@code s} on {@code separator} wherever it is not inside a quoted string (RFC 9110 &sect;5.6.4). */
    private static List<String> splitOutsideQuotes(String s, char separator) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (quoted && c == '\\' && i + 1 < s.length()) {
                current.append(c).append(s.charAt(++i));
                continue;
            }
            if (c == '"') {
                quoted = !quoted;
            } else if (c == separator && !quoted) {
                parts.add(current.toString());
                current.setLength(0);
                continue;
            }
            current.append(c);
        }
        parts.add(current.toString());
        return parts;
    }

    /** The content of a quoted string, with its quoted-pairs undone; a token is returned as it is. */
    private static String unquote(String value) {
        if (value.length() < 2 || value.charAt(0) != '"' || value.charAt(value.length() - 1) != '"') {
            return value;
        }
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 1; i < value.length() - 1; i++) {
            char c = value.charAt(i);
            if (c == '\\' && i + 1 < value.length() - 1) {
                c = value.charAt(++i);
            }
            out.append(c);
        }
        return out.toString();
    }
}
