package com.ebremer.lws.server.auth;

import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;

/**
 * Decentralized Identifiers as LWS subject identifiers: DID syntax (DID 1.1 §3.1), the document a
 * {@code did:key} expands to ("The did:key Method" v0.9, Read), and the HTTPS URL of a
 * {@code did:web}'s document ("did:web Method Specification", Read).
 *
 * <p>The self-signed controlled identifier suite "is designed to work with subject identifiers that
 * use HTTPS URIs as well as DID URIs", because a DID document extends a controlled identifier
 * document (DID 1.1 §5.1.2). It mandates no DID method. This server resolves the two that need no
 * ledger and no third-party resolver — {@code did:key}, whose document is generated locally from the
 * key the identifier embeds, and {@code did:web}, whose document is fetched over HTTPS from the
 * domain it names — and refuses every other method by name.
 *
 * @author Erich Bremer
 */
final class Dids {

    private Dids() {
    }

    static final String PREFIX = "did:";
    static final String KEY = "key";
    static final String WEB = "web";

    /** The DID methods this server resolves. */
    static final List<String> SUPPORTED_METHODS = List.of("did:key", "did:web");

    /**
     * DID 1.1 §3.1: {@code "did:" method-name ":" method-specific-id}, where a method name is lower
     * case letters and digits and the method-specific id is colon-separated runs of
     * {@code ALPHA / DIGIT / "." / "-" / "_" / pct-encoded}. No {@code /}, {@code ?} or {@code #}: a
     * DID is the identifier itself, never a DID URL.
     */
    private static final String IDCHAR = "(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})";
    private static final Pattern DID = Pattern.compile("^did:([a-z0-9]+):((?:" + IDCHAR + "*:)*" + IDCHAR + "+)$");

    /** A DNS label: letters, digits and hyphens, neither starting nor ending with a hyphen. */
    private static final Pattern LABEL = Pattern.compile("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$");

    static boolean isDid(String identifier) {
        return identifier != null && identifier.startsWith(PREFIX);
    }

    /**
     * The method name of a syntactically valid DID.
     *
     * @throws IllegalArgumentException if {@code did} is not one
     */
    static String methodOf(String did) {
        Matcher m = did == null ? null : DID.matcher(did);
        if (m == null || !m.matches()) {
            throw new IllegalArgumentException("not a syntactically valid DID");
        }
        return m.group(1);
    }

    /**
     * The DID document a {@code did:key} expands to, with the method's default {@code Multikey}
     * format: one verification method, {@code <did>#<multibase>}, controlled by the DID and referenced
     * from {@code authentication}, {@code assertionMethod}, {@code capabilityInvocation} and
     * {@code capabilityDelegation}.
     *
     * @throws IllegalArgumentException if {@code did} is not a canonically encoded did:key of a
     *                                  supported key type
     */
    static JsonObject didKeyDocument(String did) {
        if (!KEY.equals(methodOf(did))) {
            throw new IllegalArgumentException("not a did:key");
        }
        String multibase = did.substring((PREFIX + KEY + ":").length());
        Multikey.decode(multibase); // a supported key type, canonically encoded
        String methodId = did + "#" + multibase;
        JsonArrayBuilder reference = Json.createArrayBuilder().add(methodId);
        return Json.createObjectBuilder()
                .add("@context", Json.createArrayBuilder().add("https://www.w3.org/ns/did/v1.1"))
                .add("id", did)
                .add("verificationMethod", Json.createArrayBuilder().add(Json.createObjectBuilder()
                        .add("id", methodId)
                        .add("type", "Multikey")
                        .add("controller", did)
                        .add("publicKeyMultibase", multibase)))
                .add("authentication", reference)
                .add("assertionMethod", Json.createArrayBuilder().add(methodId))
                .add("capabilityInvocation", Json.createArrayBuilder().add(methodId))
                .add("capabilityDelegation", Json.createArrayBuilder().add(methodId))
                .build();
    }

    /**
     * The HTTPS URL of a {@code did:web}'s DID document:
     * <pre>
     * did:web:w3c-ccg.github.io                →  https://w3c-ccg.github.io/.well-known/did.json
     * did:web:w3c-ccg.github.io:user:alice     →  https://w3c-ccg.github.io/user/alice/did.json
     * did:web:example.com%3A3000:user:alice    →  https://example.com:3000/user/alice/did.json
     * </pre>
     * The method-specific identifier is a fully qualified domain name — never an IP address — with a
     * port only as a percent-encoded colon.
     *
     * @throws IllegalArgumentException if {@code did} is not a valid did:web
     */
    static String didWebUrl(String did) {
        if (!WEB.equals(methodOf(did))) {
            throw new IllegalArgumentException("not a did:web");
        }
        String[] parts = did.substring((PREFIX + WEB + ":").length()).split(":", -1);
        String host = parts[0];
        String port = null;
        int colon = host.toLowerCase(Locale.ROOT).indexOf("%3a");
        if (colon >= 0) {
            port = host.substring(colon + 3);
            host = host.substring(0, colon);
            if (!port.matches("[0-9]{1,5}") || Integer.parseInt(port) < 1 || Integer.parseInt(port) > 65535) {
                throw new IllegalArgumentException("did:web port is not a number from 1 to 65535");
            }
        }
        if (!isDomainName(host)) {
            throw new IllegalArgumentException("did:web must name a fully qualified domain name");
        }
        StringBuilder url = new StringBuilder("https://").append(host);
        if (port != null) {
            url.append(':').append(port);
        }
        if (parts.length == 1) {
            url.append("/.well-known");
        } else {
            for (int i = 1; i < parts.length; i++) {
                if (parts[i].isEmpty()) {
                    throw new IllegalArgumentException("did:web path has an empty segment");
                }
                url.append('/').append(parts[i]);
            }
        }
        return url.append("/did.json").toString();
    }

    /** Dot-separated DNS labels whose last label is not all digits (which also rules out IPv4). */
    static boolean isDomainName(String host) {
        if (host == null || host.isEmpty() || host.length() > 253) {
            return false;
        }
        String[] labels = host.split("\\.", -1);
        for (String label : labels) {
            if (!LABEL.matcher(label).matches()) {
                return false;
            }
        }
        return !labels[labels.length - 1].matches("[0-9]+");
    }
}
