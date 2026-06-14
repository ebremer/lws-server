package com.ebremer.lws.server.auth;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * Decides whether the server may dereference an externally-supplied URL during authentication
 * (a WebID / controlled-identifier document, or an OIDC issuer's discovery and JWKS) and WAC
 * {@code acl:agentGroup} resolution. These URLs come from an untrusted token claim or an ACL, so
 * dereferencing them is a server-side request forgery (SSRF) surface.
 *
 * <p>By default the policy permits only {@code http(s)} URLs whose host does <strong>not</strong>
 * resolve to a loopback, wildcard, link-local (which includes the cloud-metadata address
 * {@code 169.254.169.254}), private, multicast, or IPv6 unique-local address. Non-HTTP schemes such
 * as {@code file:} are <strong>always</strong> refused — this closes local-file reads via Jena's
 * {@code RDFDataMgr} loader (e.g. a {@code sub} of {@code file:///etc/passwd}). A configurable host
 * allow-list exempts specific internal hosts, and the private-address block can be turned off for a
 * trusted network or for local development.
 *
 * <p><strong>Residual risk:</strong> only the presented URL is checked, not HTTP redirect targets —
 * the underlying loaders follow redirects, so a public host that 30x-redirects to an internal
 * address is not fully prevented. Deploy where the server cannot reach sensitive internal endpoints,
 * and keep the allow-list tight.
 *
 * @author Erich Bremer
 */
public final class OutboundFetchPolicy {

    private static final Logger log = LoggerFactory.getLogger(OutboundFetchPolicy.class);

    private final boolean blockPrivateAddresses;
    private final Set<String> allowedHosts;

    public OutboundFetchPolicy(boolean blockPrivateAddresses, Set<String> allowedHosts) {
        this.blockPrivateAddresses = blockPrivateAddresses;
        this.allowedHosts = Set.copyOf(allowedHosts);
    }

    /** Permissive: {@code http(s)} to any host, no address restriction. For tests / trusted networks. */
    public static OutboundFetchPolicy permitAll() {
        return new OutboundFetchPolicy(false, Set.of());
    }

    /** The policy configured by {@code lws.fetch.*}. */
    public static OutboundFetchPolicy from(LwsConfiguration config) {
        return new OutboundFetchPolicy(config.fetchBlockPrivateAddresses(), config.fetchAllowedHosts());
    }

    /** True if {@code url} is safe to dereference under this policy. */
    public boolean permits(String url) {
        URI uri;
        try {
            uri = new URI(url);
        } catch (Exception e) {
            return false;
        }
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            log.debug("Refusing to dereference {}: only http(s) URLs are permitted", url);
            return false;
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            return false;
        }
        if (allowedHosts.contains(host.toLowerCase(Locale.ROOT))) {
            return true;
        }
        if (!blockPrivateAddresses) {
            return true;
        }
        try {
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (isBlocked(address)) {
                    log.debug("Refusing to dereference {}: host resolves to the blocked address {}",
                            url, address.getHostAddress());
                    return false;
                }
            }
            return true;
        } catch (UnknownHostException e) {
            log.debug("Refusing to dereference {}: host could not be resolved", url);
            return false; // fail closed
        }
    }

    private static boolean isBlocked(InetAddress a) {
        return a.isLoopbackAddress()        // 127.0.0.0/8, ::1
                || a.isAnyLocalAddress()    // 0.0.0.0, ::
                || a.isLinkLocalAddress()   // 169.254.0.0/16 (incl. cloud metadata), fe80::/10
                || a.isSiteLocalAddress()   // 10/8, 172.16/12, 192.168/16
                || a.isMulticastAddress()   // 224.0.0.0/4, ff00::/8
                || isUniqueLocalIpv6(a);    // fc00::/7
    }

    private static boolean isUniqueLocalIpv6(InetAddress a) {
        return a instanceof Inet6Address && (a.getAddress()[0] & 0xfe) == 0xfc;
    }
}
