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
 * <p><strong>Redirects.</strong> This class decides a single URL. Applying it to a whole fetch is
 * the caller's job, and the reason {@link HttpDocumentLoader} follows redirects itself with
 * {@code Redirect.NEVER} rather than delegating to the HTTP client: every hop is re-checked here,
 * so a public host that 30x-redirects to an internal or cloud-metadata address is refused. Route
 * outbound fetches through a {@link DocumentLoader}; a bare {@code HttpClient} or
 * {@code RDFDataMgr.loadModel(url)} follows redirects without consulting this policy.
 *
 * <p><strong>Residual risk:</strong> the address is resolved here and resolved again by the
 * fetcher, so a hostile DNS answer that changes between the two (rebinding) is not prevented.
 * Deploy where the server cannot reach sensitive internal endpoints, and keep the allow-list tight.
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

    /** The policy configured by {@code lws.fetch.*}, for authentication and WAC dereferences. */
    public static OutboundFetchPolicy from(LwsConfiguration config) {
        return new OutboundFetchPolicy(config.fetchBlockPrivateAddresses(), config.fetchAllowedHosts());
    }

    /**
     * The policy configured by {@code lws.webhook.*}, for notification delivery to client-supplied
     * inbox URLs. Kept separate from {@link #from}: being willing to dereference an internal IdP is
     * a different decision from being willing to POST notifications at an internal address.
     */
    public static OutboundFetchPolicy forDelivery(LwsConfiguration config) {
        return new OutboundFetchPolicy(config.webhookBlockPrivateAddresses(), config.webhookAllowedHosts());
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
                || isUniqueLocalIpv6(a)     // fc00::/7
                || isReservedIpv4(a)        // 100.64/10, 198.18/15, 192.0.0/24, 192.0.2/24, …
                || isTunnelledIpv4(a);      // an IPv4 address wrapped in an IPv6 one
    }

    private static boolean isUniqueLocalIpv6(InetAddress a) {
        return a instanceof Inet6Address && (a.getAddress()[0] & 0xfe) == 0xfc;
    }

    /**
     * IPv4 ranges the JDK's own predicates do not cover.
     *
     * <p>{@code isSiteLocalAddress} knows only RFC 1918. It does not know about carrier-grade NAT
     * (100.64.0.0/10), which is where a great many hosts' actual neighbours live; nor the benchmark
     * range (198.18.0.0/15); nor IETF protocol assignments (192.0.0.0/24), which is where NAT64's
     * well-known prefix and DS-Lite sit. Each is reachable from somewhere and none of them is a
     * place a WebID, an ACL group document or a webhook inbox should be.
     */
    private static boolean isReservedIpv4(InetAddress a) {
        byte[] b = a.getAddress();
        if (b.length != 4) {
            return false;
        }
        int o0 = b[0] & 0xff;
        int o1 = b[1] & 0xff;
        int o2 = b[2] & 0xff;
        return (o0 == 100 && o1 >= 64 && o1 <= 127)          // 100.64.0.0/10  carrier-grade NAT
                || (o0 == 198 && (o1 == 18 || o1 == 19))     // 198.18.0.0/15  benchmarking
                || (o0 == 192 && o1 == 0 && o2 == 0)         // 192.0.0.0/24   IETF protocol use
                || (o0 == 192 && o1 == 0 && o2 == 2)         // 192.0.2.0/24   TEST-NET-1
                || (o0 == 198 && o1 == 51 && o2 == 100)      // 198.51.100.0/24 TEST-NET-2
                || (o0 == 203 && o1 == 0 && o2 == 113)       // 203.0.113.0/24 TEST-NET-3
                || o0 == 0                                   // 0.0.0.0/8      "this network"
                || o0 >= 240;                                // 240.0.0.0/4    reserved, incl. 255/8
    }

    /**
     * An IPv6 address that is really an IPv4 one in disguise, checked against the IPv4 rules.
     *
     * <p>Three encodings reach the same host by a name none of the IPv6 predicates recognise:
     * IPv4-mapped ({@code ::ffff:a.b.c.d}), IPv4-compatible ({@code ::a.b.c.d}), 6to4
     * ({@code 2002:aabb:ccdd::/48}, which carries the IPv4 address in bytes 2–5) and the NAT64
     * well-known prefix ({@code 64:ff9b::/96}, bytes 12–15). Without this,
     * {@code http://[::ffff:169.254.169.254]/} walks straight past a guard whose whole purpose is
     * to refuse {@code http://169.254.169.254/}.
     */
    private static boolean isTunnelledIpv4(InetAddress a) {
        if (!(a instanceof Inet6Address)) {
            return false;
        }
        byte[] b = a.getAddress();
        byte[] embedded = null;
        if ((b[0] & 0xff) == 0x20 && (b[1] & 0xff) == 0x02) {
            embedded = new byte[] {b[2], b[3], b[4], b[5]};                      // 6to4
        } else if ((b[0] & 0xff) == 0x00 && (b[1] & 0xff) == 0x64
                && (b[2] & 0xff) == 0xff && (b[3] & 0xff) == 0x9b) {
            embedded = new byte[] {b[12], b[13], b[14], b[15]};                  // NAT64 64:ff9b::/96
        } else if (isAllZero(b, 0, 10)) {
            // ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible). The JDK usually normalises the
            // mapped form to an Inet4Address, but not when it arrives as a literal in a URL.
            embedded = new byte[] {b[12], b[13], b[14], b[15]};
        }
        if (embedded == null) {
            return false;
        }
        try {
            InetAddress inner = InetAddress.getByAddress(embedded);
            return inner.isLoopbackAddress() || inner.isAnyLocalAddress()
                    || inner.isLinkLocalAddress() || inner.isSiteLocalAddress()
                    || inner.isMulticastAddress() || isReservedIpv4(inner);
        } catch (UnknownHostException e) {
            return true; // four bytes cannot fail to parse; if they somehow do, refuse
        }
    }

    private static boolean isAllZero(byte[] b, int from, int to) {
        for (int i = from; i < to; i++) {
            if (b[i] != 0) {
                return false;
            }
        }
        return true;
    }
}
