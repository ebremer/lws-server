package com.ebremer.lws.server.core;

import java.util.Locale;

/**
 * Helpers for translating between HTTP request paths and LWS resource IRIs, and for
 * navigating the containment hierarchy purely by IRI/path convention.
 *
 * <p>Conventions (derived from LDP / the Solid Protocol):
 * <ul>
 *   <li>A container IRI/path ends with {@code "/"}; a data resource does not.</li>
 *   <li>The storage root is the path {@code "/"}.</li>
 * </ul>
 *
 * @author Erich Bremer
 */
public final class Iris {

    private Iris() {
    }

    /** Build a resource IRI from the public base IRI and a server-relative path. */
    public static String toIri(String baseUri, String path) {
        String b = stripTrailingSlash(baseUri);
        String p = path.startsWith("/") ? path : "/" + path;
        return b + p;
    }

    /**
     * Return the server-relative path for an IRI, or {@code null} if the IRI is not within
     * this storage's base.
     */
    public static String toPath(String baseUri, String iri) {
        String b = stripTrailingSlash(baseUri);
        if (iri.equals(b)) {
            return "/";
        }
        if (iri.startsWith(b + "/")) {
            return iri.substring(b.length());
        }
        return null;
    }

    public static boolean isContainerPath(String path) {
        return path.endsWith("/");
    }

    public static boolean isRoot(String path) {
        return "/".equals(path);
    }

    /** The reserved suffix identifying a resource's linkset (metadata) resource. */
    public static final String LINKSET_SUFFIX = ".meta";

    /** The linkset (metadata) resource IRI/path for a resource, e.g. {@code /a/b} -> {@code /a/b.meta}. */
    public static String linkset(String iriOrPath) {
        return iriOrPath + LINKSET_SUFFIX;
    }

    public static boolean isLinksetPath(String path) {
        return path.endsWith(LINKSET_SUFFIX);
    }

    /** The resource path a linkset path describes, e.g. {@code /a/b.meta} -> {@code /a/b}, {@code /a/.meta} -> {@code /a/}. */
    public static String linksetTargetPath(String linksetPath) {
        return linksetPath.substring(0, linksetPath.length() - LINKSET_SUFFIX.length());
    }

    /**
     * The parent container path of a path, or {@code null} for the root.
     * The returned value always ends with {@code "/"}.
     */
    public static String parentPath(String path) {
        if (isRoot(path)) {
            return null;
        }
        String p = stripTrailingSlash(path);
        int i = p.lastIndexOf('/');
        return p.substring(0, i + 1);
    }

    /** The final path segment (no slashes), e.g. {@code "/a/b/c"} -> {@code "c"}, {@code "/a/b/"} -> {@code "b"}. */
    public static String lastSegment(String path) {
        String p = stripTrailingSlash(path);
        int i = p.lastIndexOf('/');
        return i < 0 ? p : p.substring(i + 1);
    }

    /** True if {@code path} is contained, directly or transitively, by {@code containerPath}. */
    public static boolean isWithin(String containerPath, String path) {
        if (!containerPath.endsWith("/")) {
            containerPath = containerPath + "/";
        }
        return path.startsWith(containerPath) && !path.equals(containerPath);
    }

    /**
     * Sanitize a client-supplied Slug into a safe single path segment, or {@code null} if
     * nothing usable remains. Path separators and unsafe characters are removed.
     */
    public static String sanitizeSlug(String slug) {
        if (slug == null) {
            return null;
        }
        String s = slug.trim();
        if (s.isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
                sb.append(c);
            } else {
                sb.append('-');
            }
        }
        String out = sb.toString().replaceAll("-{2,}", "-");
        // never allow a segment that is only dots (".", "..") or empty
        out = out.replaceAll("^\\.+$", "");
        out = out.replaceAll("^-+", "").replaceAll("-+$", "");
        return out.isEmpty() ? null : out;
    }

    /**
     * Map a server-relative path to a safe binary-store key (no leading slash, no traversal).
     *
     * @throws LwsException 400 if the path attempts directory traversal.
     */
    public static String binaryKey(String path) {
        String p = path.startsWith("/") ? path.substring(1) : path;
        for (String seg : p.split("/")) {
            if (seg.equals("..")) {
                throw LwsException.badRequest("Illegal path segment");
            }
        }
        return p;
    }

    public static String stripTrailingSlash(String s) {
        if (s.length() > 1 && s.endsWith("/")) {
            return s.substring(0, s.length() - 1);
        }
        return s;
    }

    public static String lowerHost(String host) {
        return host == null ? null : host.toLowerCase(Locale.ROOT);
    }
}
