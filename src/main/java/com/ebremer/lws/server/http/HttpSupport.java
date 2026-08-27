package com.ebremer.lws.server.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.IfMatch;
import com.ebremer.lws.server.core.IfNoneMatch;
import com.ebremer.lws.server.core.Iris;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.core.LwsResource;
import com.ebremer.lws.server.core.ResourceService.TypeHint;
import com.ebremer.lws.server.core.ResourceType;
import com.ebremer.lws.server.rdf.RdfFormats;
import com.ebremer.lws.server.vocab.LDP;
import com.ebremer.lws.server.vocab.LWS;

/**
 * HTTP plumbing shared by the LWS servlets: header formatting, Link relations, conditional
 * requests, body reading and request-type interpretation.
 *
 * @author Erich Bremer
 */
public final class HttpSupport {

    private HttpSupport() {
    }

    /** Link relation pointing to the storage description resource. */
    public static final String REL_STORAGE_DESCRIPTION = LWS.NS + "storageDescription";

    /** JSON Merge Patch (RFC 7386). */
    public static final String MERGE_PATCH = "application/merge-patch+json";
    /** JSON Patch (RFC 6902). */
    public static final String JSON_PATCH = "application/json-patch+json";
    /**
     * What an RDF resource accepts on PATCH. Merge patch is deliberately absent: it is not defined
     * over RDF, and advertising it is what got it used (finding H21). SPARQL Update is the
     * RDF patch mechanism, and {@link #ACCEPT_PATCH_JSON} still offers both JSON patch dialects on
     * the opaque JSON resources where they do have a meaning.
     */
    public static final String ACCEPT_PATCH = "application/sparql-update";
    /** {@code Accept-Patch} for JSON resources and linksets: JSON Merge Patch or JSON Patch. */
    public static final String ACCEPT_PATCH_JSON = MERGE_PATCH + ", " + JSON_PATCH;

    /** Media type for Search/Type Index requests and responses (lws10-searchindex). */
    public static final String LWS_JSON = "application/lws+json";
    /** The JSON-LD context referenced by {@code application/lws+json} documents. */
    public static final String LWS_JSON_CONTEXT = LWS.JSON_CONTEXT;

    /**
     * Refuse a request body that does not declare a JSON media type.
     *
     * <p>Cheap, and it belongs before the body is read: it turns "some bytes arrived and the parser
     * disagreed" into an answer the client can act on, and on an endpoint that accepts anonymous
     * requests it is the first thing that costs an attacker something.
     */
    public static void requireJsonContentType(jakarta.servlet.http.HttpServletRequest req) {
        String ct = req.getContentType();
        String mt = ct == null ? "" : RdfFormats.stripParameters(ct);
        if (!mt.equals(LWS_JSON) && !mt.equals("application/ld+json") && !mt.equals("application/json")) {
            throw LwsException.unsupportedMediaType("Request body must be " + LWS_JSON);
        }
    }

    public static final String ACCEPT_POST =
            String.join(", ", RdfFormats.TURTLE, RdfFormats.JSONLD, RdfFormats.NTRIPLES, "*/*");

    private static final Pattern LINK_PATTERN =
            Pattern.compile("<([^>]*)>\\s*;\\s*rel\\s*=\\s*\"?([^\";,]+)\"?", Pattern.CASE_INSENSITIVE);

    /**
     * IMF-fixdate, the one date format RFC 9110 §5.6.7 requires a sender to produce.
     *
     * <p>Not {@code RFC_1123_DATE_TIME}: that formatter does not zero-pad the day of month, so it
     * emits {@code Tue, 3 Jun 2008} where the grammar demands {@code Tue, 03 Jun 2008} — a
     * {@code Last-Modified} a strict cache is entitled to ignore, for eleven days of every month.
     * {@code Locale.ROOT} because the day and month names are protocol tokens, not display text.
     */
    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", java.util.Locale.ROOT)
                    .withZone(ZoneId.of("GMT"));

    /**
     * The date formats a recipient must ACCEPT, which is not the one it must send.
     *
     * <p>RFC 9110 §5.6.7 requires a recipient to parse all three historical forms, and making the
     * sender strict does not license making the reader strict. Reusing the IMF-fixdate formatter for
     * both turned an unpadded day — {@code Tue, 3 Jun 2008}, which is exactly what <em>this
     * server</em> emitted until the sender was fixed — into an unparseable header, and an
     * unparseable {@code If-Modified-Since} is silently treated as absent: a full {@code 200} where
     * a {@code 304} was due, for any client still echoing a validator it cached earlier.
     */
    private static final DateTimeFormatter HTTP_DATE_LENIENT = new DateTimeFormatterBuilder()
            .parseCaseInsensitive()
            .parseLenient()
            .append(DateTimeFormatter.RFC_1123_DATE_TIME)
            .toFormatter(java.util.Locale.ROOT)
            .withZone(ZoneId.of("GMT"));

    public static String httpDate(Instant instant) {
        return HTTP_DATE.format(instant);
    }

    /**
     * Mark a response whose content depends on <em>who asked</em>, so no shared cache keeps it.
     *
     * <p>Several statuses are heuristically cacheable even with no explicit freshness information —
     * RFC 9110 §15.1 lists {@code 204} and {@code 405} among them — so a per-principal answer at one
     * of those statuses can be stored and replayed to a different client. The container listing and
     * the access and search endpoints already set this; OPTIONS and the {@code Allow} header need it
     * for the same reason, now that both are computed per principal.
     */
    public static void setPrivateNoStore(HttpServletResponse response) {
        response.setHeader("Cache-Control", "private, no-store");
    }

    /**
     * Set the headers a {@code 401} response should carry: {@code WWW-Authenticate}, and a
     * {@code Link} to the storage description so a client can discover how to authenticate without
     * a hardcoded URI (lws10-core SHOULD).
     */
    public static void setUnauthorizedHeaders(HttpServletResponse response, LwsConfiguration config) {
        // Every scheme this storage accepts, not just Bearer. RFC 9110 §11.6.1 lets a 401 carry
        // more than one challenge, and a client that can only do DPoP had no way to discover that
        // this server speaks it — which is what the README claims discovery is for. The
        // scheme-specific 401s raised inside AuthenticationFilter still name the single scheme the
        // request actually used; this is the generic one, raised where no scheme was chosen yet.
        response.setHeader("WWW-Authenticate", "Bearer realm=\"lws\"");
        response.addHeader("WWW-Authenticate", "DPoP realm=\"lws\"");
        if (!config.samlTrustedIssuers().isEmpty()) {
            response.addHeader("WWW-Authenticate", "SAML2 realm=\"lws\"");
        }
        response.addHeader("Link",
                "<" + config.storageDescriptionIri() + ">; rel=\"" + REL_STORAGE_DESCRIPTION + "\"");
    }

    /** Content type for structured error responses (RFC 9457). */
    public static final String PROBLEM_JSON = "application/problem+json";

    /** Render an RFC 9457 problem-details object for an error status. */
    public static byte[] problemJson(int status, String detail) {
        return jakarta.json.Json.createObjectBuilder()
                .add("type", "about:blank")
                .add("title", reasonPhrase(status))
                .add("status", status)
                .add("detail", detail == null ? "" : detail)
                .build().toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String reasonPhrase(int status) {
        return switch (status) {
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 409 -> "Conflict";
            case 412 -> "Precondition Failed";
            case 413 -> "Content Too Large";
            case 415 -> "Unsupported Media Type";
            case 416 -> "Range Not Satisfiable";
            case 428 -> "Precondition Required";
            case 429 -> "Too Many Requests";
            case 500 -> "Internal Server Error";
            case 507 -> "Insufficient Storage";
            default -> "Error";
        };
    }

    /**
     * Read the whole request body, refusing anything larger than {@code maxBytes} with {@code 413}.
     *
     * <p>An unbounded {@code readAllBytes()} here is reachable before any authorization decision:
     * the body is materialised so it can be parsed, and only then does the service layer decide
     * whether the caller may write at all. A few concurrent multi-gigabyte requests therefore
     * exhaust the heap regardless of quota or ACLs, and a body over 2 GiB throws
     * {@link OutOfMemoryError}, which is an {@code Error} and escapes the servlet's
     * {@code catch (RuntimeException)}.
     *
     * @param maxBytes the limit, or {@code <= 0} for unlimited
     */
    public static byte[] readBody(HttpServletRequest request, long maxBytes) throws IOException {
        if (maxBytes <= 0) {
            try (var in = request.getInputStream()) {
                return in.readAllBytes();
            }
        }
        // Refuse on the declared length first, so an honest oversized request costs nothing.
        long declared = request.getContentLengthLong();
        if (declared > maxBytes) {
            throw tooLarge(maxBytes);
        }
        try (var in = request.getInputStream()) {
            // One byte past the limit distinguishes "exactly at the limit" from "over it" for a
            // chunked body, whose length is not known in advance.
            byte[] body = in.readNBytes((int) Math.min(maxBytes + 1, Integer.MAX_VALUE));
            if (body.length > maxBytes) {
                throw tooLarge(maxBytes);
            }
            return body;
        }
    }

    private static LwsException tooLarge(long maxBytes) {
        return new LwsException(413, "Request body exceeds the maximum of " + maxBytes
                + " bytes (lws.max-request-bytes)");
    }

    /**
     * Determine what the client asked to create from any {@code Link: rel="type"} headers,
     * recognising both LDP and LWS interaction-model IRIs.
     */
    public static TypeHint parseTypeHint(HttpServletRequest request) {
        for (String header : headers(request, "Link")) {
            Matcher m = LINK_PATTERN.matcher(header);
            while (m.find()) {
                String uri = m.group(1);
                String rel = m.group(2).trim();
                if (!rel.equalsIgnoreCase("type")) {
                    continue;
                }
                if (uri.equals(LDP.CONTAINER) || uri.equals(LDP.BASIC_CONTAINER) || uri.equals(LWS.Container.getURI())) {
                    return TypeHint.CONTAINER;
                }
                if (uri.equals(LDP.NON_RDF_SOURCE)) {
                    return TypeHint.NON_RDF_SOURCE;
                }
                if (uri.equals(LDP.RDF_SOURCE)) {
                    return TypeHint.RDF_SOURCE;
                }
            }
        }
        return TypeHint.AUTO;
    }

    /**
     * Parse all {@code Link} request headers into a relation &rarr; target-URIs map, preserving order.
     * Used to apply {@code Prefer: set-linkset} (RFC 7240) metadata from a resource write.
     *
     * <p>{@code rel="type"} used to be dropped wholesale here, on the grounds that
     * {@link #parseTypeHint} consumes it. It consumes the <em>interaction models</em> — is this a
     * container, a data resource, opaque bytes — which is a different claim from "this document is
     * about a {@code schema:Person}". Dropping both closed off the searchindex spec's preferred way
     * of declaring a resource's type, and left a binary resource, which has no content graph to
     * assert one in, with no way to carry a type at all. The interaction models are still excluded,
     * and {@code LinksetService} bounds what remains.
     */
    public static Map<String, List<String>> parseLinks(HttpServletRequest request) {
        Map<String, List<String>> links = new LinkedHashMap<>();
        for (String header : headers(request, "Link")) {
            Matcher m = LINK_PATTERN.matcher(header);
            while (m.find()) {
                String uri = m.group(1);
                String rel = m.group(2).trim();
                if (rel.equalsIgnoreCase("type") && INTERACTION_MODEL_LINKS.contains(uri)) {
                    continue; // consumed by parseTypeHint as the interaction model
                }
                links.computeIfAbsent(rel, k -> new ArrayList<>()).add(uri);
            }
        }
        return links;
    }

    /** Exactly the IRIs {@link #parseTypeHint} recognises, so the two cannot disagree about them. */
    private static final Set<String> INTERACTION_MODEL_LINKS = Set.of(
            LDP.CONTAINER, LDP.BASIC_CONTAINER, LWS.Container.getURI(),
            LDP.NON_RDF_SOURCE, LDP.RDF_SOURCE);

    /**
     * Media types a browser will execute in the origin that served them. Content stored by one
     * agent is read back by another, so serving these inline makes any writable storage a stored
     * cross-site-scripting vector against every other user of the same origin — including the
     * session-authenticated management console at {@code /app/}.
     */
    private static final Set<String> ACTIVE_CONTENT_TYPES = Set.of(
            "text/html", "application/xhtml+xml", "image/svg+xml", "application/xml", "text/xml",
            "application/xslt+xml", "text/xsl");

    /**
     * Harden a non-RDF (client-supplied) representation against being executed by a browser.
     *
     * <p>The stored media type is echoed back verbatim, so the defence is layered rather than a
     * rewrite: {@code nosniff} stops a browser inferring an executable type from the bytes, a
     * restrictive sandbox CSP neuters scripts and same-origin access if it renders anyway, and
     * anything in {@link #ACTIVE_CONTENT_TYPES} is additionally forced to download rather than
     * render. The media type itself is preserved so clients that fetch the bytes still see it.
     */
    public static void setContentSecurityHeaders(HttpServletResponse response, LwsResource meta) {
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Content-Security-Policy", "sandbox; default-src 'none'");
        String type = meta.contentType() == null ? "" : stripParameters(meta.contentType());
        if (ACTIVE_CONTENT_TYPES.contains(type)) {
            response.setHeader("Content-Disposition",
                    "attachment; filename=\"" + safeFilename(meta.iri()) + "\"");
        }
    }

    /** A quoted-string-safe filename derived from the resource IRI's last path segment. */
    private static String safeFilename(String iri) {
        String name = Iris.lastSegment(iri);
        if (name == null || name.isBlank()) {
            return "download";
        }
        StringBuilder sb = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            // Header-safe subset: no quotes, backslashes or control characters to break out of the
            // quoted string, and no non-ASCII (which would need RFC 5987 encoding).
            sb.append(c >= 0x20 && c < 0x7f && c != '"' && c != '\\' ? c : '_');
        }
        return sb.toString();
    }

    private static String stripParameters(String mediaType) {
        int semi = mediaType.indexOf(';');
        return (semi < 0 ? mediaType : mediaType.substring(0, semi)).trim().toLowerCase(java.util.Locale.ROOT);
    }

    /**
     * Declare that the response varies by {@code fieldName}, without dropping a field another filter
     * has already declared.
     *
     * <p>{@code setHeader("Vary", "Accept")} <em>replaces</em>. Once the CORS filter began adding
     * {@code Vary: Origin} ahead of the servlets, every content-negotiated response then overwrote it
     * — so the responses that vary by both said they varied only by {@code Accept}, and a shared
     * cache could serve one origin's {@code Access-Control-Allow-Origin} to a request from another.
     * A repeated field name is skipped rather than appended, so a path that declares the same field
     * twice does not emit it twice.
     */
    public static void vary(HttpServletResponse response, String fieldName) {
        for (String existing : response.getHeaders("Vary")) {
            for (String token : existing.split(",")) {
                if (token.trim().equalsIgnoreCase(fieldName)) {
                    return;
                }
            }
        }
        response.addHeader("Vary", fieldName);
    }

    /** Set ETag, Last-Modified and the LWS/LDP Link headers common to all resource responses. */
    public static void setResourceHeaders(HttpServletResponse response, LwsResource meta, LwsConfiguration config) {
        if (meta.etag() != null) {
            response.setHeader("ETag", meta.quotedEtag());
        }
        if (meta.modified() != null) {
            response.setHeader("Last-Modified", httpDate(meta.modified()));
        }
        response.addHeader("Link", "<" + config.storageDescriptionIri() + ">; rel=\"" + REL_STORAGE_DESCRIPTION + "\"");
        // Metadata discovery (lws10-core): the parent container (rel="up", non-root only) and the
        // resource's linkset (metadata) resource.
        if (meta.parentIri() != null) {
            response.addHeader("Link", "<" + meta.parentIri() + ">; rel=\"up\"");
        }
        response.addHeader("Link",
                "<" + Iris.linkset(meta.iri()) + ">; rel=\"linkset\"; type=\"application/linkset+json\"");
        addTypeLinks(response, meta.type());
    }

    public static void addTypeLinks(HttpServletResponse response, ResourceType type) {
        response.addHeader("Link", "<" + LDP.RESOURCE + ">; rel=\"type\"");
        switch (type) {
            case CONTAINER -> {
                response.addHeader("Link", "<" + LDP.BASIC_CONTAINER + ">; rel=\"type\"");
                response.addHeader("Link", "<" + LWS.Container.getURI() + ">; rel=\"type\"");
            }
            case RDF_SOURCE -> {
                response.addHeader("Link", "<" + LDP.RDF_SOURCE + ">; rel=\"type\"");
                response.addHeader("Link", "<" + LWS.DataResource.getURI() + ">; rel=\"type\"");
            }
            case NON_RDF_SOURCE -> {
                response.addHeader("Link", "<" + LDP.NON_RDF_SOURCE + ">; rel=\"type\"");
                response.addHeader("Link", "<" + LWS.DataResource.getURI() + ">; rel=\"type\"");
            }
        }
    }

    /** True if an {@code If-None-Match} header matches the resource's etag (so GET => 304). */
    public static boolean ifNoneMatchMatches(HttpServletRequest request, LwsResource meta) {
        return ifNoneMatchMatches(request, meta.etag());
    }

    /**
     * True if the request's {@code If-None-Match} names {@code etag}, so a {@code GET} answers
     * {@code 304}.
     *
     * <p>The two conditional headers share {@link IfMatch}'s entity-tag list syntax but <em>not</em>
     * its meaning when absent: no {@code If-Match} means "no precondition, proceed", while no
     * {@code If-None-Match} means "not a revalidation, send the body". {@link IfMatch#matches}
     * answers the first, so every caller has to test presence itself — which is why this exists, and
     * why the storage-description servlet used to hand-roll a substring test
     * ({@code inm.contains(etag)}) that matched a tag merely appearing inside a longer one.
     *
     * <p>The comparison is exact, not {@link IfMatch#namesState}: a client revalidating the Turtle
     * representation must not be told {@code 304} for the JSON-LD one (finding M21).
     */
    public static boolean ifNoneMatchMatches(HttpServletRequest request, String etag) {
        IfMatch tags = IfMatch.of(request.getHeader("If-None-Match"));
        return tags.isPresent() && etag != null && tags.matches(etag);
    }

    /** True if an {@code If-Modified-Since} precondition shows the resource is unchanged (so GET => 304). */
    public static boolean ifModifiedSinceNotModified(HttpServletRequest request, LwsResource meta) {
        return notModifiedSince(request, meta.modified());
    }

    /**
     * Evaluate an {@code If-Modified-Since} conditional against a last-modified instant. Returns
     * {@code true} (=> 304) when the entity has not changed since the supplied HTTP date.
     * {@code If-None-Match} takes precedence per RFC 9110, so this yields {@code false} when an
     * {@code If-None-Match} header is present.
     */
    public static boolean notModifiedSince(HttpServletRequest request, Instant modified) {
        if (modified == null || request.getHeader("If-None-Match") != null) {
            return false;
        }
        String header = request.getHeader("If-Modified-Since");
        if (header == null) {
            return false;
        }
        try {
            Instant since = ZonedDateTime.parse(header.trim(), HTTP_DATE_LENIENT).toInstant();
            return !modified.truncatedTo(ChronoUnit.SECONDS).isAfter(since);
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    /**
     * The request's {@code If-Match} precondition, to be carried into the write transaction that
     * honours it. The comparison itself lives in {@link IfMatch} so that the early check here and
     * the authoritative compare-and-swap inside the transaction cannot disagree about which tags
     * match (findings H23, M18).
     */
    public static IfMatch ifMatch(HttpServletRequest request) {
        return IfMatch.of(request.getHeader("If-Match"));
    }

    /**
     * The request's {@code If-None-Match} precondition <em>as a write precondition</em>, carried into
     * the transaction that honours it (finding L28). For the read-side meaning, which is the
     * opposite when the header is absent, see {@link #ifNoneMatchMatches}.
     */
    public static IfNoneMatch ifNoneMatch(HttpServletRequest request) {
        return IfNoneMatch.of(request.getHeader("If-None-Match"));
    }

    /**
     * Parse a single HTTP {@code Range} request against a known entity length (RFC 7233).
     *
     * @return {@code {start,end}} (inclusive) for a satisfiable single byte range; {@code {-1}} when
     *         the range is a byte range but unsatisfiable (the caller responds 416); or {@code null}
     *         when there is no usable single byte range (the caller serves the full entity, 200).
     */
    public static long[] parseByteRange(String header, long size) {
        if (header == null) {
            return null;
        }
        String h = header.trim();
        if (!h.startsWith("bytes=")) {
            return null;
        }
        String spec = h.substring("bytes=".length()).trim();
        if (spec.isEmpty() || spec.contains(",")) {
            return null; // multiple ranges unsupported: serve the full entity
        }
        int dash = spec.indexOf('-');
        if (dash < 0) {
            return null;
        }
        String startStr = spec.substring(0, dash).trim();
        String endStr = spec.substring(dash + 1).trim();
        try {
            long start;
            long end;
            if (startStr.isEmpty()) {
                if (endStr.isEmpty()) {
                    return null;
                }
                long suffix = Long.parseLong(endStr);
                if (suffix <= 0) {
                    return new long[] {-1};
                }
                start = Math.max(0, size - suffix);
                end = size - 1;
            } else {
                start = Long.parseLong(startStr);
                end = endStr.isEmpty() ? size - 1 : Math.min(Long.parseLong(endStr), size - 1);
            }
            if (start < 0 || start >= size || start > end) {
                return new long[] {-1};
            }
            return new long[] {start, end};
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static List<String> headers(HttpServletRequest request, String name) {
        List<String> out = new ArrayList<>();
        var e = request.getHeaders(name);
        while (e != null && e.hasMoreElements()) {
            out.add(e.nextElement());
        }
        return out;
    }
}
