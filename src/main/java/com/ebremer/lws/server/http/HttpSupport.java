package com.ebremer.lws.server.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.Iris;
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
    /** {@code Accept-Patch} for RDF resources: SPARQL Update or JSON Merge Patch (via JSON-LD). */
    public static final String ACCEPT_PATCH = "application/sparql-update, " + MERGE_PATCH;
    /** {@code Accept-Patch} for JSON resources and linksets: JSON Merge Patch or JSON Patch. */
    public static final String ACCEPT_PATCH_JSON = MERGE_PATCH + ", " + JSON_PATCH;

    /** Media type for Search/Type Index requests and responses (lws10-searchindex). */
    public static final String LWS_JSON = "application/lws+json";
    /** The JSON-LD context referenced by {@code application/lws+json} documents. */
    public static final String LWS_JSON_CONTEXT = LWS.JSON_CONTEXT;

    public static final String ACCEPT_POST =
            String.join(", ", RdfFormats.TURTLE, RdfFormats.JSONLD, RdfFormats.NTRIPLES, "*/*");

    private static final Pattern LINK_PATTERN =
            Pattern.compile("<([^>]*)>\\s*;\\s*rel\\s*=\\s*\"?([^\";,]+)\"?", Pattern.CASE_INSENSITIVE);

    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.RFC_1123_DATE_TIME.withZone(ZoneId.of("GMT"));

    public static String httpDate(Instant instant) {
        return HTTP_DATE.format(instant);
    }

    /**
     * Set the headers a {@code 401} response should carry: {@code WWW-Authenticate}, and a
     * {@code Link} to the storage description so a client can discover how to authenticate without
     * a hardcoded URI (lws10-core SHOULD).
     */
    public static void setUnauthorizedHeaders(HttpServletResponse response, LwsConfiguration config) {
        response.setHeader("WWW-Authenticate", "Bearer realm=\"lws\"");
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
            case 415 -> "Unsupported Media Type";
            case 416 -> "Range Not Satisfiable";
            case 428 -> "Precondition Required";
            case 500 -> "Internal Server Error";
            case 507 -> "Insufficient Storage";
            default -> "Error";
        };
    }

    public static byte[] readBody(HttpServletRequest request) throws IOException {
        try (var in = request.getInputStream()) {
            return in.readAllBytes();
        }
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
     * Parse all {@code Link} request headers into a relation &rarr; target-URIs map, preserving order
     * and excluding the interaction-model {@code rel="type"} (consumed by {@link #parseTypeHint}).
     * Used to apply {@code Prefer: set-linkset} (RFC 7240) metadata from a resource write.
     */
    public static Map<String, List<String>> parseLinks(HttpServletRequest request) {
        Map<String, List<String>> links = new LinkedHashMap<>();
        for (String header : headers(request, "Link")) {
            Matcher m = LINK_PATTERN.matcher(header);
            while (m.find()) {
                String uri = m.group(1);
                String rel = m.group(2).trim();
                if (rel.equalsIgnoreCase("type")) {
                    continue;
                }
                links.computeIfAbsent(rel, k -> new ArrayList<>()).add(uri);
            }
        }
        return links;
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
        String header = request.getHeader("If-None-Match");
        if (header == null || meta.etag() == null) {
            return false;
        }
        return matchesEtag(header, meta);
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
            Instant since = ZonedDateTime.parse(header.trim(), HTTP_DATE).toInstant();
            return !modified.truncatedTo(ChronoUnit.SECONDS).isAfter(since);
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    /** True if an {@code If-Match} precondition is present and fails (so write => 412). */
    public static boolean ifMatchFails(HttpServletRequest request, LwsResource meta) {
        String header = request.getHeader("If-Match");
        if (header == null) {
            return false;
        }
        return !matchesEtag(header, meta);
    }

    private static boolean matchesEtag(String header, LwsResource meta) {
        String h = header.trim();
        if (h.equals("*")) {
            return true;
        }
        String quoted = meta.quotedEtag();
        for (String token : h.split(",")) {
            String t = token.trim();
            if (t.startsWith("W/")) {
                t = t.substring(2).trim();
            }
            if (t.equals(quoted) || t.equals(meta.etag())) {
                return true;
            }
        }
        return false;
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
