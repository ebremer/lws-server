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

    /**
     * The reserved suffix identifying a resource's access-control resource.
     *
     * <p>It lives here rather than in the Web Access Control engine because it is a fact about the
     * IRI space, not about authorization: the router diverts these paths and the create path must
     * refuse them, in both authorization modes and whether or not WAC is even wired up.
     */
    public static final String ACL_SUFFIX = ".acl";

    /** The reserved suffix identifying a resource's linkset (metadata) resource. */
    public static final String LINKSET_SUFFIX = ".meta";

    public static boolean isAclPath(String path) {
        return path.endsWith(ACL_SUFFIX);
    }

    /**
     * True if the final segment of {@code path} is reserved for a resource's ACL or linkset.
     *
     * <p>The trailing slash is stripped first, so a <em>container</em> named {@code .acl} is
     * reserved too. The router does not divert that form today, but {@code Slug: .acl/} reaches it
     * in one header and it sits one path normalization away from a name that matters — this guard
     * must be a superset of what the router hides, never a subset. Matching is case-insensitive for
     * the same reason: {@code .ACL} is not diverted today, and over-reserving is free while
     * under-reserving is the bug.
     */
    public static boolean hasReservedSuffix(String path) {
        String segment = stripTrailingSlash(path).toLowerCase(Locale.ROOT);
        return segment.endsWith(ACL_SUFFIX) || segment.endsWith(LINKSET_SUFFIX);
    }

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
     * Mint a fresh, opaque binary-store key, unrelated to any resource IRI.
     *
     * <p>Keys used to be the request path itself, which made the blob store a second namespace
     * addressed by client-chosen names. That is unsafe in two ways. Resource IRIs are compared
     * case-sensitively, but NTFS and default APFS/HFS+ are not, so {@code /c/Secret} and
     * {@code /c/secret} — two resources with independent owners and ACLs — resolved to the
     * <em>same file</em>: writing one silently replaced the other's bytes while its metadata still
     * described the old content. And a data resource at {@code /a} needs a file where a resource at
     * {@code /a/b} needs a directory, so the pair collided into a permanent 500.
     *
     * <p>An opaque key also makes commit-ordered writes possible: a new version goes to a key no
     * reader can reach yet, so the live bytes are only retired once the metadata naming them has
     * committed. The key is stored per resource in {@code lws:binaryKey}, so existing path-derived
     * keys keep resolving and are retired naturally as their resources are rewritten.
     */
    public static String newBinaryKey() {
        String hex = java.util.UUID.randomUUID().toString().replace("-", "");
        // Two levels of fan-out keep directory sizes reasonable on large stores.
        return hex.substring(0, 2) + "/" + hex.substring(2, 4) + "/" + hex;
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
