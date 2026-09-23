package com.ebremer.lws.server;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import com.ebremer.lws.server.core.Iris;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * All runtime configuration for the LWS server, as a plain immutable POJO with <em>no</em>
 * framework dependencies. This is deliberate: the Spring Boot bootstrap and a future bare
 * Eclipse Jetty bootstrap both build the server from one of these, so configuration never
 * couples to Spring.
 *
 * <p>Values are resolved (lowest to highest precedence) from: built-in defaults, an optional
 * {@code lws.properties} on the classpath, an optional {@code ./lws.properties} file, and
 * finally {@code -Dlws.*} system properties.
 *
 * @author Erich Bremer
 */
public final class LwsConfiguration {

    private static final Logger log = LoggerFactory.getLogger(LwsConfiguration.class);

    /** Which RDF backend the metadata store uses. */
    public enum RdfBackend { TDB2, REMOTE }

    /** Which authorization model the server enforces. */
    public enum AccessControl { OWNER, WAC }

    private final String baseUri;        // normalized, no trailing slash
    private final int port;
    private final Path dataDir;
    private final String systemPrefix;   // e.g. "/.lws"
    private final Set<String> ownerWebIds;
    private final boolean publicReadDefault;
    private final boolean devOpen;
    private final AccessControl accessControl;
    private final long wacGroupCacheSeconds;
    private final long wacGroupFailureCacheSeconds;
    private final int wacMaxGroupFetchesPerDecision;

    private final RdfBackend rdfBackend;
    private final String sparqlQueryEndpoint;
    private final String sparqlUpdateEndpoint;
    private final String sparqlGspEndpoint;
    private final boolean sparqlRemoteAcknowledged;

    // Optional interactive OIDC login for the Wicket UI (resource-server token validation
    // does not require these; they only enable browser sign-in).
    private final String oidcDiscoveryUri;
    private final String oidcClientId;
    private final String oidcClientSecret;
    private final boolean uiDevLogin;

    // SAML 2.0 authentication suite (out-of-band trust).
    private final List<String> samlCertPaths;
    private final Set<String> samlTrustedIssuers;
    private final String samlAudience;

    // Webhook delivery tuning.
    private final int webhookMaxAttempts;
    private final long webhookRetryBackoffMillis;
    private final int webhookMaxConsecutiveFailures;
    private final int webhookThreads;
    private final int webhookQueueCapacity;
    private final int webhookMaxInFlightPerHost;
    private final long subscriptionPurgeIntervalSeconds;

    // Search/Type Index services (lws10-searchindex).
    private final boolean searchIndexEnabled;
    private final int searchIndexPageSize;

    // Container listing pagination: a listing larger than this is split into pages.
    private final int containerPageSize;

    // Access Requests & Grants (lws10-core/lws-access-requests).
    private final boolean accessRequestsEnabled;
    private final String accessControllerInbox;

    // Storage quota: maximum total binary-content bytes (0 = unlimited).
    private final long quotaMaxBytes;

    // DPoP: require a server-issued nonce in proofs (RFC 9449 §8).
    private final long maxRequestBytes;
    private final long linksetMaxBytes;
    private final boolean maskForbiddenAsNotFound;
    private final boolean dpopRequireNonce;
    private final boolean dpopRequire;
    private final int dpopJtiCacheSize;

    // Bounds on the SSI-CID subject-document dereference, which an unauthenticated credential aims.
    private final long ssiCidDocumentCacheSeconds;
    private final long ssiCidDocumentFailureCacheSeconds;

    // Audience binding for JWT credentials: which `aud` values this storage accepts, and whether a
    // credential must carry one at all. Without this check a token minted for another storage (or,
    // for OpenID, for another relying party of the same provider) is replayable here.
    private final Set<String> acceptedAudiences;
    private final boolean audienceRequired;
    private final long tokenMaxLifetimeMs;

    // LWS authorization (lws10-core, Authorization): the OAuth 2.0 access tokens this storage
    // accepts, the authorization server embedded in it, and whether an authentication credential
    // presented directly — this server's behaviour before the access-token baseline — is still
    // honoured as an additional mechanism.
    private final boolean oauthEnabled;
    private final long oauthAccessTokenLifetimeSeconds;
    private final Set<String> oauthTrustedIssuers;
    private final boolean oauthAcceptCredentials;

    // Notifications: whether the envelope names the agent that made the change (lws10-core says the
    // actor SHOULD be omitted by default and MAY be configurable).
    private final boolean notificationsIncludeActor;

    // SPARQL Update: hosts that LOAD/SERVICE may fetch from (empty = none; SSRF guard).
    private final Set<String> sparqlUpdateAllowedHosts;

    // Outbound-fetch SSRF guard for auth (WebID/OIDC) and WAC agentGroup dereferences.
    private final boolean fetchBlockPrivateAddresses;
    private final Set<String> fetchAllowedHosts;

    // The same guard for notification delivery, which posts to client-supplied inbox URLs. Kept
    // separate from the auth guard: trusting an internal IdP is a different decision from being
    // willing to POST notifications at an internal address.
    private final boolean webhookBlockPrivateAddresses;
    private final Set<String> webhookAllowedHosts;

    // Subscription creation limits: unauthenticated, uncapped, never-expiring subscriptions are
    // both an SSRF amplifier and a slow-down on every write in the server.
    private final boolean subscriptionsAllowAnonymous;
    private final int subscriptionsMaxPerSubscriber;
    private final long subscriptionsMaxLifetimeSeconds;

    // Hosts whose JSON-LD @context documents may be dereferenced; empty refuses all remote contexts.
    private final Set<String> jsonLdAllowedContextHosts;

    // Embedded Fuseki SPARQL endpoint over the local dataset (opt-in; bypasses WAC).
    private final boolean sparqlEndpointEnabled;
    private final int sparqlEndpointPort;
    private final String sparqlEndpointDataset;
    private final boolean sparqlEndpointReadOnly;
    private final boolean sparqlEndpointLoopback;
    private final String sparqlEndpointPublicUrl;

    // Reverse-proxy / TLS posture: the server terminates plain HTTP; TLS is expected at a front proxy.
    private final boolean behindProxy;   // trust X-Forwarded-* / Forwarded (RFC 7239) from that proxy
    private final boolean requireHttps;  // refuse a non-HTTPS, non-loopback base URI at startup
    private final long hstsMaxAgeSeconds; // Strict-Transport-Security lifetime; 0 disables the header

    // Cross-origin access (CORS) for browser applications; empty = no cross-origin access at all.
    private final Set<String> corsAllowedOrigins;
    private final boolean corsAllowsAnyOrigin;
    private final long corsMaxAgeSeconds;

    // Direct TLS termination via ACME (Let's Encrypt) — the bare-Jetty launcher's alternative to a
    // TLS-terminating reverse proxy. The server obtains and renews a certificate via the HTTP-01
    // challenge and serves HTTPS itself.
    private final boolean tlsEnabled;
    private final int tlsPort;            // HTTPS listen port
    private final int tlsHttpPort;        // HTTP listen port (serves the ACME challenge; redirects to HTTPS)
    private final Path tlsDir;            // holds the ACME account key, domain key, and certificate chain
    private final String acmeDirectoryUrl;
    private final List<String> acmeDomains;
    private final String acmeEmail;
    private final boolean acmeAcceptTos;
    private final int acmeRenewBeforeDays;

    private LwsConfiguration(Properties p) {
        String base = get(p, "lws.base-uri", "http://localhost:8080");
        URI baseUriParsed = requireBaseUri(base);
        this.baseUri = stripTrailingSlash(base);
        // The listen port defaults to the port written in the base URI. Behind a reverse proxy the
        // base URI is the external address (e.g. https://host/lws), whose port says nothing about
        // where the proxy forwards to, so lws.listen-port can name that port separately.
        this.port = getInt(p, "lws.listen-port",
                baseUriParsed.getPort() > 0 ? baseUriParsed.getPort() : 8080, 1, 65535);
        this.dataDir = getPath(p, "lws.data-dir", "lws-data");
        this.systemPrefix = "/" + get(p, "lws.system-prefix", ".lws").replaceAll("^/+", "").replaceAll("/+$", "");
        this.ownerWebIds = parseSet(get(p, "lws.owners", ""));
        this.publicReadDefault = getBoolean(p, "lws.public-read", false);
        this.devOpen = getBoolean(p, "lws.dev.open", false);
        this.accessControl = getEnum(p, "lws.access-control", AccessControl.class, AccessControl.OWNER);
        // WAC resolves acl:agentGroup membership by dereferencing the group document, at an
        // address the requester's own ACL names. Caching bounds how often that happens; the
        // separate, much shorter failure TTL exists so an unreachable group is not re-fetched once
        // per request while a transient outage still clears in seconds rather than minutes. The
        // per-decision cap bounds an ACL that names many distinct unreachable groups.
        // Floored at one second rather than zero: an authorization decision made inside a
        // transaction resolves group membership from this cache alone, so disabling it would
        // silently deny every group-based authorization on every write.
        this.wacGroupCacheSeconds = getLong(p, "lws.wac.group-cache-seconds", 300, 1, 86_400);
        this.wacGroupFailureCacheSeconds =
                getLong(p, "lws.wac.group-failure-cache-seconds", 30, 0, 86_400);
        this.wacMaxGroupFetchesPerDecision =
                getInt(p, "lws.wac.max-group-fetches-per-decision", 8, 0, 1_000);

        this.rdfBackend = getEnum(p, "lws.sparql.mode", RdfBackend.class, RdfBackend.TDB2);
        this.sparqlQueryEndpoint = get(p, "lws.sparql.query", "");
        this.sparqlUpdateEndpoint = get(p, "lws.sparql.update", "");
        this.sparqlGspEndpoint = get(p, "lws.sparql.gsp", "");
        this.sparqlRemoteAcknowledged = getBoolean(p, "lws.sparql.remote.accept-no-transactions", false);
        validateRemoteBackend();

        this.oidcDiscoveryUri = get(p, "lws.oidc.discovery-uri", "");
        this.oidcClientId = get(p, "lws.oidc.client-id", "");
        this.oidcClientSecret = get(p, "lws.oidc.client-secret", "");
        this.uiDevLogin = getBoolean(p, "lws.ui.dev-login", false);
        this.samlCertPaths = parseList(get(p, "lws.saml.idp-certificates", ""));
        this.samlTrustedIssuers = parseSet(get(p, "lws.saml.trusted-issuers", ""));
        this.samlAudience = get(p, "lws.saml.audience", "");

        this.webhookMaxAttempts = getInt(p, "lws.webhook.max-attempts", 5, 1, Integer.MAX_VALUE);
        this.webhookRetryBackoffMillis = getLong(p, "lws.webhook.retry-backoff-ms", 2000, 0, Long.MAX_VALUE);
        this.webhookMaxConsecutiveFailures = getInt(p, "lws.webhook.max-consecutive-failures", 10, 1, Integer.MAX_VALUE);
        this.webhookThreads = getInt(p, "lws.webhook.threads", 4, 1, 256);
        this.webhookQueueCapacity = getInt(p, "lws.webhook.queue-capacity", 1000, 1, 1_000_000);
        this.webhookMaxInFlightPerHost = getInt(p, "lws.webhook.max-in-flight-per-host", 4, 1, 1024);
        this.subscriptionPurgeIntervalSeconds =
                getLong(p, "lws.subscription.purge-interval-seconds", 3600, 0, Long.MAX_VALUE);

        this.searchIndexEnabled = getBoolean(p, "lws.search-index.enabled", true);
        this.searchIndexPageSize = getInt(p, "lws.search-index.page-size", 100, 1, Integer.MAX_VALUE);
        this.containerPageSize = getInt(p, "lws.container.page-size", 1000, 1, Integer.MAX_VALUE);
        this.accessRequestsEnabled = getBoolean(p, "lws.access-requests.enabled", true);
        this.accessControllerInbox = get(p, "lws.access-requests.controller-inbox", "");
        this.quotaMaxBytes = getLong(p, "lws.quota.max-bytes", 0, 0, Long.MAX_VALUE);
        // Bodies are buffered whole before the write is authorized, so this is the bound that keeps
        // an unauthenticated request from costing arbitrary heap. Capped at Integer.MAX_VALUE
        // because the body lands in a single byte[].
        this.maxRequestBytes =
                getLong(p, "lws.max-request-bytes", 64L * 1024 * 1024, 0, Integer.MAX_VALUE);
        // The linkset is the one stored JSON document a client can grow by repeated patching, so
        // the request-body bound above does not bound it: a PATCH composes with what is already
        // stored (finding N5). Bounded in bytes because that is the unit an operator can reason
        // about, and because a JSON Patch `copy` from "" doubles the document without deepening it
        // by more than one level.
        this.linksetMaxBytes =
                getLong(p, "lws.linkset.max-bytes", 1024L * 1024, 1024, Integer.MAX_VALUE);
        // Existence is resolved before authorization, so 403-versus-404 told a client which
        // resources are there. Masked by default; an operator who would rather their clients see
        // an honest 403 can turn it off, at the cost of that disclosure.
        this.maskForbiddenAsNotFound = getBoolean(p, "lws.mask-forbidden-as-not-found", true);
        this.dpopRequireNonce = getBoolean(p, "lws.dpop.require-nonce", false);
        this.dpopRequire = getBoolean(p, "lws.dpop.require", false);
        // Sized from the expected DPoP request rate, not picked as a round number: an entry that is
        // evicted for size has not expired, so the proof that wrote it is replayable again.
        this.dpopJtiCacheSize = getInt(p, "lws.dpop.jti-cache-size", 100_000, 1_000, 10_000_000);
        // The SSI-CID subject document is dereferenced from a URL the (unauthenticated) credential
        // names, so it is cached; the failure TTL is much shorter so a real outage clears quickly.
        this.ssiCidDocumentCacheSeconds =
                getLong(p, "lws.ssi-cid.document-cache-seconds", 300, 1, 86_400);
        this.ssiCidDocumentFailureCacheSeconds =
                getLong(p, "lws.ssi-cid.document-failure-cache-seconds", 30, 1, 86_400);

        // Default audiences: this storage's own identifiers. An operator whose provider mints a
        // different value (e.g. an OAuth client id) lists it in lws.audience.
        Set<String> audiences = parseSet(get(p, "lws.audience", ""));
        this.acceptedAudiences = audiences.isEmpty() ? Set.of(this.baseUri, this.baseUri + "/")
                : Set.copyOf(audiences);
        this.audienceRequired = getBoolean(p, "lws.audience.require", true);
        // Cap at ten years so the millisecond conversion cannot overflow.
        this.tokenMaxLifetimeMs =
                getLong(p, "lws.token.max-lifetime-seconds", 3600, 0, 315_360_000L) * 1000L;

        this.oauthEnabled = getBoolean(p, "lws.oauth.enabled", true);
        // lws10-core RECOMMENDS 300 seconds or less; an hour is the most this server will mint.
        this.oauthAccessTokenLifetimeSeconds =
                getLong(p, "lws.oauth.access-token-lifetime-seconds", 300, 1, 3600);
        Set<String> issuers = new LinkedHashSet<>();
        for (String issuer : parseSet(get(p, "lws.oauth.trusted-issuers", ""))) {
            URI parsed = requireUri("lws.oauth.trusted-issuers", issuer);
            if (parsed.getRawQuery() != null || parsed.getRawFragment() != null) {
                throw error("lws.oauth.trusted-issuers", issuer,
                        "an issuer identifier with no query or fragment (RFC 8414 section 2)");
            }
            issuers.add(issuer);
        }
        this.oauthTrustedIssuers = issuers;
        this.oauthAcceptCredentials = getBoolean(p, "lws.oauth.accept-authentication-credentials", true);
        this.notificationsIncludeActor = getBoolean(p, "lws.notifications.include-actor", false);
        Set<String> loadHosts = new LinkedHashSet<>();
        for (String host : parseSet(get(p, "lws.sparql-update.allowed-hosts", ""))) {
            loadHosts.add(host.toLowerCase(Locale.ROOT));
        }
        this.sparqlUpdateAllowedHosts = loadHosts;

        this.fetchBlockPrivateAddresses = getBoolean(p, "lws.fetch.block-private-addresses", true);
        Set<String> fetchHosts = new LinkedHashSet<>();
        for (String host : parseSet(get(p, "lws.fetch.allowed-hosts", ""))) {
            fetchHosts.add(host.toLowerCase(Locale.ROOT));
        }
        this.fetchAllowedHosts = fetchHosts;

        this.webhookBlockPrivateAddresses = getBoolean(p, "lws.webhook.block-private-addresses", true);
        Set<String> webhookHosts = new LinkedHashSet<>();
        for (String host : parseSet(get(p, "lws.webhook.allowed-hosts", ""))) {
            webhookHosts.add(host.toLowerCase(Locale.ROOT));
        }
        this.webhookAllowedHosts = webhookHosts;

        this.subscriptionsAllowAnonymous = getBoolean(p, "lws.subscriptions.allow-anonymous", false);
        this.subscriptionsMaxPerSubscriber =
                getInt(p, "lws.subscriptions.max-per-subscriber", 100, 1, Integer.MAX_VALUE);
        this.subscriptionsMaxLifetimeSeconds =
                getLong(p, "lws.subscriptions.max-lifetime-seconds", 2_592_000L, 0, 315_360_000L);

        Set<String> contextHosts = new LinkedHashSet<>();
        for (String host : parseSet(get(p, "lws.jsonld.allowed-context-hosts", ""))) {
            contextHosts.add(host.toLowerCase(Locale.ROOT));
        }
        this.jsonLdAllowedContextHosts = contextHosts;

        this.sparqlEndpointEnabled = getBoolean(p, "lws.sparql.endpoint.enabled", false);
        this.sparqlEndpointPort = getInt(p, "lws.sparql.endpoint.port", 3030, 1, 65535);
        this.sparqlEndpointDataset = "/" + get(p, "lws.sparql.endpoint.dataset", "lws")
                .replaceAll("^/+", "").replaceAll("/+$", "");
        this.sparqlEndpointReadOnly = getBoolean(p, "lws.sparql.endpoint.read-only", true);
        this.sparqlEndpointLoopback = getBoolean(p, "lws.sparql.endpoint.loopback", true);
        this.sparqlEndpointPublicUrl = get(p, "lws.sparql.endpoint.public-url", "");

        // Cross-origin access for browser applications. Empty (the default) means the filter is not
        // installed at all; the literal "*" allows any origin, which validateCors() then refuses to
        // combine with a storage that has no authorization.
        Set<String> origins = new LinkedHashSet<>();
        boolean anyOrigin = false;
        for (String origin : parseSet(get(p, "lws.cors.allowed-origins", ""))) {
            if (origin.equals("*")) {
                anyOrigin = true;
            } else {
                origins.add(requireOrigin(origin));
            }
        }
        this.corsAllowsAnyOrigin = anyOrigin;
        this.corsAllowedOrigins = origins;
        this.corsMaxAgeSeconds = getLong(p, "lws.cors.max-age-seconds", 600, 0, 86_400);

        this.behindProxy = getBoolean(p, "lws.behind-proxy", false);
        this.requireHttps = getBoolean(p, "lws.require-https", false);
        // One year, the usual floor for a host to be considered for HSTS preloading. Emitted only on
        // responses that really went out over TLS, and only when lws.base-uri is https.
        this.hstsMaxAgeSeconds = getLong(p, "lws.hsts.max-age-seconds", 31_536_000L, 0, 315_360_000L);
        validateTransportSecurity();

        this.tlsEnabled = getBoolean(p, "lws.tls.enabled", false);
        this.tlsPort = getInt(p, "lws.tls.port", 443, 1, 65535);
        this.tlsHttpPort = getInt(p, "lws.tls.http-port", 80, 1, 65535);
        this.tlsDir = getPath(p, "lws.tls.dir", dataDir.resolve("tls").toString());
        String acmeUrl = get(p, "lws.tls.acme.directory-url", "https://acme-v02.api.letsencrypt.org/directory");
        requireUri("lws.tls.acme.directory-url", acmeUrl);
        this.acmeDirectoryUrl = acmeUrl;
        List<String> domains = parseList(get(p, "lws.tls.acme.domains", ""));
        this.acmeDomains = domains.isEmpty() ? hostOf(baseUri) : domains;
        this.acmeEmail = get(p, "lws.tls.acme.email", "");
        this.acmeAcceptTos = getBoolean(p, "lws.tls.acme.accept-terms-of-service", false);
        this.acmeRenewBeforeDays = getInt(p, "lws.tls.acme.renew-before-days", 30, 1, Integer.MAX_VALUE);
        validateTls();
        // Last, so that every parse and every other posture check reports first: this one is about
        // what the configuration as a whole adds up to.
        validateAuthorizationPosture();
    }

    /**
     * Refuse the two configurations that are development-only and look like production.
     *
     * <p>Neither is a new restriction on what the server can do — both postures remain available.
     * What changes is that they now have to be <em>asked for</em>. Every finding behind this check
     * had the same shape: an operator who did not know they were in the development posture, because
     * the development posture was the default and said nothing.
     *
     * <p>There is deliberately no {@code lws.profile=production}. A profile that only tightens when
     * it is set is a no-op for exactly the operator it is meant to protect; secure-by-default means
     * moving the default, not offering an opt-in to safety.
     */
    private void validateAuthorizationPosture() {
        if (ownerWebIds.isEmpty() && !devOpen) {
            String wac = accessControl == AccessControl.WAC
                    ? " In WAC mode the bootstrapped root ACL grants the public Read, Write and "
                            + "Control, and it is written once — so configuring owners later does not "
                            + "undo it by itself."
                    : "";
            throw new LwsConfigurationException("lws.owners is empty, which is open mode: every read, "
                    + "write and control decision is permitted for every client, including anonymous "
                    + "ones." + wac + " Configure at least one owner WebID (DidKeyTool mints one "
                    + "offline — see lws.example.properties), or set lws.dev.open=true to run this "
                    + "way deliberately.");
        }
        if (uiDevLogin && !isLoopbackBaseUri() && !devOpen) {
            throw new LwsConfigurationException("lws.ui.dev-login=true lets any client sign in as any "
                    + "WebID, and lws.base-uri (" + baseUri + ") is not a loopback address. Sign in "
                    + "with an ID token instead, or set lws.dev.open=true.");
        }
        if (devOpen && requireHttps) {
            throw new LwsConfigurationException("lws.dev.open=true declares a development "
                    + "authorization posture and lws.require-https=true declares a production "
                    + "transport posture. That combination is a development configuration promoted to "
                    + "production; pick one.");
        }
        if (devOpen && behindProxy) {
            log.warn("lws.dev.open=true together with lws.behind-proxy=true: development "
                    + "authorization behind a fronting proxy. Check this is a development deployment.");
        }
        if (devOpen && !isLoopbackBaseUri()) {
            log.warn("lws.dev.open=true with a non-loopback lws.base-uri ({}): development "
                    + "authorization is reachable from the network.", baseUri);
        }
        if (!oauthEnabled && oauthTrustedIssuers.isEmpty()) {
            log.warn("lws.oauth.enabled=false and lws.oauth.trusted-issuers is empty: this storage "
                    + "names no authorization server, so its 401 challenges cannot carry the as_uri "
                    + "lws10-core requires and no client can obtain an access token for it.{}",
                    oauthAcceptCredentials ? " Authentication credentials presented directly are "
                            + "still accepted (lws.oauth.accept-authentication-credentials)." : "");
        }
        validateCors();
        validateTlsPosture();
    }

    /**
     * The two TLS postures are alternatives, and combining them produces the opposite of both.
     *
     * <p><b>Refused: {@code lws.tls.enabled} with {@code lws.behind-proxy}.</b> The server terminates
     * TLS itself <em>and</em> trusts {@code X-Forwarded-Proto} from a proxy that is not there. Any
     * client can then send that header, {@code request.isSecure()} answers true, and the
     * HTTP-to-HTTPS redirect — and the {@code 503} that holds requests back until the certificate has
     * been obtained (finding M28) — are both skipped for a plaintext request. The two settings
     * describe mutually exclusive deployments; the README says to use one or the other.
     *
     * <p><b>Warned: an {@code https} base URI without {@code lws.behind-proxy} or
     * {@code lws.tls.enabled}.</b> Nothing terminates TLS, so no request is ever
     * {@code isSecure()} — which means the {@code Secure} flag never reaches the console's session
     * cookie and no {@code Strict-Transport-Security} is ever emitted, while the configuration looks
     * like a production HTTPS deployment. If a proxy really is in front, say so.
     */
    private void validateTlsPosture() {
        if (tlsEnabled && behindProxy) {
            throw new LwsConfigurationException("lws.tls.enabled=true terminates TLS in this server "
                    + "while lws.behind-proxy=true trusts X-Forwarded-Proto from a fronting proxy. "
                    + "With both, any client can claim its plaintext request arrived over TLS and skip "
                    + "the HTTPS redirect entirely. Pick one: terminate TLS here, or at a proxy.");
        }
        if (baseUri.startsWith("https://") && !behindProxy && !tlsEnabled) {
            log.warn("lws.base-uri is https ({}) but nothing terminates TLS: lws.behind-proxy is "
                    + "false and lws.tls.enabled is false. No request will be secure, so the session "
                    + "cookie will not be marked Secure and no Strict-Transport-Security will be "
                    + "sent. Set lws.behind-proxy=true if a TLS-terminating proxy is in front.",
                    baseUri);
        }
    }

    /**
     * {@code lws.cors.allowed-origins=*} cannot be combined with a storage that has no authorization.
     *
     * <p>The combination is not merely permissive, it is a complete giveaway, and it is the shape a
     * browser-app developer is most likely to reach for: {@code lws.base-uri=http://localhost:8080},
     * {@code lws.dev.open=true} — where {@code DefaultAccessPolicy} permits every read <em>and every
     * write</em> anonymously — plus {@code *} to make the app work. The authority in open mode is
     * ambient (being able to reach the port), so there is no token an attacking page would have to
     * hold; {@code *} converts "reachable from this machine" into "readable and writable by any
     * website the developer visits". No credentials are ever sent, which is exactly why that argument
     * does not save it: there is nothing to borrow because nothing is required.
     *
     * <p>Refused rather than warned, following {@code lws.dev.open} + {@code lws.require-https}: a
     * development authorization posture and a production sharing posture cannot both be true. An
     * explicit origin list works in open mode, and {@code *} works with real authorization.
     *
     * <p>{@code lws.public-read=true} is the weaker version of the same thing — reads only, and
     * deliberately chosen — so it earns a warning instead.
     */
    private void validateCors() {
        if (!corsAllowsAnyOrigin) {
            return;
        }
        if (isOpenMode()) {
            throw new LwsConfigurationException("lws.cors.allowed-origins=* together with open mode "
                    + "(no lws.owners) would let any website a browser visits read and write this "
                    + "entire storage: open mode authorizes every request, so an attacking page needs "
                    + "no credential at all. List the origins your application is served from, or "
                    + "configure lws.owners.");
        }
        if (publicReadDefault) {
            log.warn("lws.cors.allowed-origins=* with lws.public-read=true: every website a browser "
                    + "visits can read this storage's public content from that browser. Intended for "
                    + "a deliberately public storage; list origins instead if it is not one.");
        }
    }

    /**
     * An origin in the form a browser actually sends it: lower-cased, with a default port removed.
     *
     * <p>The serialization of a web origin omits the scheme's default port, so a browser sends
     * {@code https://app.example} and never {@code https://app.example:443}. Applied to the
     * configured values <em>and</em> to the incoming header, so that an operator who writes the port
     * explicitly gets a configuration that works rather than one that validates, starts, and
     * silently refuses every request from that origin.
     */
    public static String normalizeOrigin(String origin) {
        String o = origin.trim().toLowerCase(Locale.ROOT);
        if (o.startsWith("https://") && o.endsWith(":443")) {
            return o.substring(0, o.length() - 4);
        }
        if (o.startsWith("http://") && o.endsWith(":80")) {
            return o.substring(0, o.length() - 3);
        }
        return o;
    }

    /** Validate an allowed CORS origin: scheme + host, and no path, as the {@code Origin} header has. */
    private static String requireOrigin(String value) {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException e) {
            throw error("lws.cors.allowed-origins", value, "a web origin (e.g. https://app.example)");
        }
        String scheme = uri.getScheme();
        if (scheme == null || uri.getHost() == null
                || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))
                || (uri.getPath() != null && !uri.getPath().isEmpty())) {
            throw error("lws.cors.allowed-origins", value,
                    "an http(s) origin with no path (e.g. https://app.example or https://app.example:8443)");
        }
        // Normalized to the form a browser actually sends, so that writing the default port
        // explicitly is a working configuration rather than a silent refusal.
        return normalizeOrigin(value);
    }

    /**
     * The remote SPARQL backend needs three endpoints, and needs the operator to know what it costs.
     *
     * <p><b>The endpoints (finding M27).</b> {@code lws.sparql.mode=REMOTE} used to be accepted with
     * all three blank, producing an {@code RDFConnectionRemote} with no destination that died much
     * later as an opaque Jena {@code ARQException} naming no configuration key — exactly what
     * {@link LwsConfigurationException} exists to prevent. All three are required, and each must be
     * an absolute {@code http(s)} URL.
     *
     * <p>They are deliberately <em>not</em> put through the outbound-fetch SSRF policy. That policy
     * exists for addresses chosen by an untrusted token or ACL; these are chosen by the operator, and
     * the documented example ({@code http://localhost:3030/lws/query}) is precisely the private
     * address the policy blocks. Refusing it would refuse the recommended deployment.
     *
     * <p><b>The acknowledgement (finding M16).</b> Remote SPARQL has no cross-statement transaction,
     * so {@code RemoteSparqlRdfStore.read} and {@code write} are the same autocommitting method. Every
     * guarantee this server builds on a real unit of work is therefore absent on that backend, and
     * silently: the {@code If-Match} compare-and-swap that makes a conditional write safe (H23),
     * ACL and linkset erasure committing with the delete that requires it (H24), blob writes retiring
     * only after the metadata naming them commits (H13/H14), the linkset read-modify-write (M18) and
     * quota enforcement all degrade to a sequence of independent requests. A concurrent reader between
     * the two halves of {@code ResourceRegistry.put} sees a spurious {@code 404}; two concurrent POSTs
     * pick the same name. Rather than pretend otherwise, the mode has to be asked for.
     */
    private void validateRemoteBackend() {
        if (rdfBackend != RdfBackend.REMOTE) {
            return;
        }
        // The acknowledgement is checked first, before the endpoints. Whether to use this backend at
        // all is the decision; which URLs to point it at is a detail of carrying that decision out,
        // and an operator should not have to fix three endpoints before being told the mode itself
        // costs them the guarantees below.
        if (!sparqlRemoteAcknowledged) {
            throw new LwsConfigurationException("lws.sparql.mode=REMOTE is experimental: remote SPARQL "
                    + "has no cross-statement transaction, so conditional writes (If-Match) are not a "
                    + "compare-and-swap, a delete does not erase the resource's ACL and linkset "
                    + "atomically with it, binary content and its metadata can diverge, and the "
                    + "storage quota is advisory. Set lws.sparql.remote.accept-no-transactions=true to "
                    + "run this way deliberately, or use the default lws.sparql.mode=TDB2.");
        }
        requireHttpEndpoint("lws.sparql.query", sparqlQueryEndpoint);
        requireHttpEndpoint("lws.sparql.update", sparqlUpdateEndpoint);
        requireHttpEndpoint("lws.sparql.gsp", sparqlGspEndpoint);
    }

    /** Require a configured endpoint to be present and an absolute {@code http(s)} URL. */
    private static void requireHttpEndpoint(String key, String value) {
        if (value == null || value.isBlank()) {
            throw new LwsConfigurationException("lws.sparql.mode=REMOTE requires " + key
                    + " (the remote service's SPARQL Query, Update and Graph Store Protocol endpoints).");
        }
        URI uri = requireUri(key, value);
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw error(key, value, "an http:// or https:// URL");
        }
    }

    /** ACME registration requires a domain and agreement to the CA's terms of service. */
    private void validateTls() {
        if (!tlsEnabled) {
            return;
        }
        if (!acmeAcceptTos) {
            throw new LwsConfigurationException("lws.tls.enabled=true requires "
                    + "lws.tls.acme.accept-terms-of-service=true (ACME registration agrees to the CA's ToS).");
        }
        if (acmeDomains.isEmpty()) {
            throw new LwsConfigurationException("lws.tls.enabled=true requires at least one domain "
                    + "(set lws.tls.acme.domains, or a host in lws.base-uri).");
        }
    }

    private static List<String> hostOf(String baseUri) {
        String host = URI.create(baseUri).getHost();
        return host == null ? List.of() : List.of(host);
    }

    /**
     * DPoP and WebID/OIDC assume the storage is reached over TLS in production. Because the server
     * terminates plain HTTP (TLS is expected at a reverse proxy), this validates the <em>public</em>
     * base URI rather than the listening socket: a non-HTTPS, non-loopback base URI is refused at
     * startup when {@code lws.require-https=true}, and warned about otherwise.
     */
    private void validateTransportSecurity() {
        String scheme = URI.create(baseUri).getScheme();
        if ("https".equalsIgnoreCase(scheme) || isLoopbackBaseUri()) {
            return;
        }
        String message = "lws.base-uri is not HTTPS (" + baseUri + "); DPoP and WebID/OIDC assume TLS "
                + "in production. Terminate TLS at a reverse proxy, set lws.base-uri to the external "
                + "https:// URL, and set lws.behind-proxy=true.";
        if (requireHttps) {
            throw new LwsConfigurationException(message + " Refusing to start (lws.require-https=true).");
        }
        log.warn("{} Set lws.require-https=true to enforce.", message);
    }

    /** True when the base-URI host is a loopback address (local development; TLS not required). */
    private boolean isLoopbackBaseUri() {
        return isLoopbackHost(URI.create(baseUri).getHost());
    }

    /**
     * True when {@code host} is a loopback <em>address</em>, or the name {@code localhost}.
     *
     * <p>Only IP literals are classified, and only by what they are. The previous test asked whether
     * the string started with {@code 127.} or contained {@code ::1}, which made the public address
     * {@code [2001:db8::1]} and the ordinary domain {@code 127.example.com} both count as loopback —
     * and therefore exempt from the HTTPS requirement they most needed. DNS is deliberately not
     * resolved: where a name points today is a fact about somebody's zone file, not about this
     * deployment, and honouring it would let a rebind switch the exemption on and off from outside.
     */
    public static boolean isLoopbackHost(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String h = host.trim().toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        if (h.equals("localhost")) {
            return true;
        }
        try {
            return InetAddress.ofLiteral(h).isLoopbackAddress();
        } catch (IllegalArgumentException notAnIpLiteral) {
            return false;
        }
    }

    /** The configuration file looked for on the classpath and in the working directory. */
    private static final String PROPERTIES_FILE = "lws.properties";

    /**
     * Load configuration from the standard sources.
     *
     * <p>A source that is <em>absent</em> is fine — both are optional. A source that is present and
     * cannot be read is not: every setting would silently fall back to its default, and the defaults
     * are the development ones. Empty {@code lws.owners} means open mode, where
     * {@code DefaultAccessPolicy} permits everything; {@code lws.base-uri} would revert to
     * {@code http://localhost:8080} at the same moment, making every minted IRI and every DPoP
     * {@code htu} wrong.
     *
     * <p>The failure this guards is the <em>hardening</em> step: an operator does
     * {@code chown root:root lws.properties; chmod 600} because the file holds
     * {@code lws.oidc.client-secret}, while the service runs unprivileged. The resulting
     * {@code AccessDeniedException} used to be swallowed and the storage came up world-writable,
     * with one INFO line as the only trace. It now refuses to start.
     */
    public static LwsConfiguration load() {
        Properties p = new Properties();
        // classpath:lws.properties
        try (InputStream in = LwsConfiguration.class.getClassLoader().getResourceAsStream(PROPERTIES_FILE)) {
            if (in != null) {
                p.load(in);
            }
        } catch (IOException | IllegalArgumentException e) {
            // getResourceAsStream has already answered "is it there?", so anything arriving here is
            // a real failure: an unreadable jar entry, or a malformed Unicode escape in the file.
            throw new LwsConfigurationException("Cannot read " + PROPERTIES_FILE + " from the classpath: " + e);
        }
        // ./lws.properties
        mergeOptionalFile(p, Path.of(PROPERTIES_FILE));
        // -Dlws.* system properties win
        System.getProperties().stringPropertyNames().stream()
                .filter(k -> k.startsWith("lws."))
                .forEach(k -> p.setProperty(k, System.getProperty(k)));
        return new LwsConfiguration(p);
    }

    /**
     * Merge a properties file into {@code p} if there is one.
     *
     * <p>Absent is the only tolerable failure. This used to be guarded by an
     * {@code isRegularFile()} test whose catch then swallowed every {@code IOException} as though it
     * were asking the same question again — so a file that existed and could not be read looked
     * exactly like no file at all, and the server came up on the development defaults.
     */
    static void mergeOptionalFile(Properties p, Path file) {
        try (InputStream in = Files.newInputStream(file)) {
            p.load(in);
        } catch (NoSuchFileException absent) {
            // No configuration file here, which is a supported way to run.
        } catch (IOException | IllegalArgumentException e) {
            throw new LwsConfigurationException("Cannot read " + file.toAbsolutePath() + ": " + e);
        }
    }

    /** Build directly from a Properties object (used by tests and embedded launchers). */
    public static LwsConfiguration of(Properties p) {
        return new LwsConfiguration(p);
    }

    private static String get(Properties p, String key, String def) {
        String v = p.getProperty(key);
        return (v == null || v.isBlank()) ? def : v.trim();
    }

    // ----- typed, validating accessors: every failure names the key, the value, and what was expected -----

    private static int getInt(Properties p, String key, int def, int min, int max) {
        String v = get(p, key, Integer.toString(def));
        int value;
        try {
            value = Integer.parseInt(v);
        } catch (NumberFormatException e) {
            throw error(key, v, "an integer");
        }
        if (value < min || value > max) {
            throw error(key, v, "an integer in [" + min + ", " + max + "]");
        }
        return value;
    }

    private static long getLong(Properties p, String key, long def, long min, long max) {
        String v = get(p, key, Long.toString(def));
        long value;
        try {
            value = Long.parseLong(v);
        } catch (NumberFormatException e) {
            throw error(key, v, "an integer");
        }
        if (value < min || value > max) {
            throw error(key, v, "an integer in [" + min + ", " + max + "]");
        }
        return value;
    }

    private static boolean getBoolean(Properties p, String key, boolean def) {
        String v = get(p, key, Boolean.toString(def)).toLowerCase(Locale.ROOT);
        return switch (v) {
            case "true" -> true;
            case "false" -> false;
            default -> throw error(key, v, "true or false");
        };
    }

    private static <E extends Enum<E>> E getEnum(Properties p, String key, Class<E> type, E def) {
        String v = get(p, key, def.name());
        try {
            return Enum.valueOf(type, v.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw error(key, v, "one of " + Arrays.toString(type.getEnumConstants()));
        }
    }

    private static Path getPath(Properties p, String key, String def) {
        String v = get(p, key, def);
        try {
            return Path.of(v);
        } catch (InvalidPathException e) {
            throw error(key, v, "a valid filesystem path");
        }
    }

    /** Validate that {@code lws.base-uri} is an absolute {@code http(s)} URL and return it parsed. */
    private static URI requireBaseUri(String value) {
        URI uri = requireUri("lws.base-uri", value);
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw error("lws.base-uri", value, "an http:// or https:// URL");
        }
        return uri;
    }

    /** Validate that {@code value} is an absolute URI (scheme + host present) and return it parsed. */
    private static URI requireUri(String key, String value) {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException e) {
            throw error(key, value, "a valid URI");
        }
        if (uri.getScheme() == null || uri.getHost() == null) {
            throw error(key, value, "an absolute URI with a scheme and host (e.g. https://storage.example)");
        }
        return uri;
    }

    private static LwsConfigurationException error(String key, String value, String expected) {
        return new LwsConfigurationException(
                "Invalid configuration: " + key + " must be " + expected + " (got \"" + value + "\").");
    }

    private static List<String> parseList(String csv) {
        if (csv == null || csv.isBlank()) {
            return List.of();
        }
        return Arrays.stream(csv.split("[,\\s]+")).filter(s -> !s.isBlank()).map(String::trim).toList();
    }

    private static Set<String> parseSet(String csv) {
        if (csv == null || csv.isBlank()) {
            return Collections.emptySet();
        }
        return new LinkedHashSet<>(Arrays.stream(csv.split("[,\\s]+"))
                .filter(s -> !s.isBlank())
                .map(String::trim)
                .toList());
    }

    private static String stripTrailingSlash(String s) {
        return s.length() > 1 && s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    // ----- Accessors -----

    public String baseUri() {
        return baseUri;
    }

    /**
     * The path of {@code lws.base-uri} without a trailing slash ({@code "/lws"} for
     * {@code https://host/lws}), or {@code ""} when the storage is at the root of its host. A proxy
     * strips it before the request reaches this server, so it is where the browser-facing session
     * cookie belongs.
     */
    public String basePath() {
        String path = URI.create(baseUri).getRawPath();
        return path == null || path.equals("/") ? "" : path;
    }

    /** The HTTP listen port: {@code lws.listen-port}, else the port of {@code lws.base-uri}, else 8080. */
    public int port() {
        return port;
    }

    /** The IRI of the storage root container. */
    public String storageRootIri() {
        return baseUri + "/";
    }

    /**
     * The canonical URI of the storage (lws10-core, Discovery): the {@code id} of the storage
     * description, the target of every {@code rel="https://www.w3.org/ns/lws#storage"} link, the
     * {@code realm} of this storage's challenges and the one {@code aud} its access tokens carry.
     *
     * <p>It is the root container's URI, as lws10-core permits, because the realm has to logically
     * contain every resource a client sends a token to — a URI no resource path starts with could
     * not — and because it is the value this server's access grants and notifications have always
     * carried as {@code storage}.
     */
    public String storageIri() {
        return storageRootIri();
    }

    public Path dataDir() {
        return dataDir;
    }

    public Path tdb2Dir() {
        return dataDir.resolve("tdb2");
    }

    public Path blobDir() {
        return dataDir.resolve("blobs");
    }

    public Path keysDir() {
        return dataDir.resolve("keys");
    }

    /** The system path prefix, e.g. {@code "/.lws"}. */
    public String systemPrefix() {
        return systemPrefix;
    }

    public String storageDescriptionPath() {
        return systemPrefix + "/storage-description";
    }

    public String subscriptionsPath() {
        return systemPrefix + "/subscriptions";
    }

    public String jwksPath() {
        return systemPrefix + "/jwks";
    }

    public String typeIndexPath() {
        return systemPrefix + "/type-index";
    }

    public String typeSearchPath() {
        return systemPrefix + "/type-search";
    }

    public String accessRequestsPath() {
        return systemPrefix + "/access-requests";
    }

    public String accessGrantsPath() {
        return systemPrefix + "/access-grants";
    }

    /** The OAuth 2.0 token endpoint of the embedded authorization server (RFC 8693 token exchange). */
    public String tokenPath() {
        return systemPrefix + "/token";
    }

    /** Where the embedded authorization server publishes its metadata (lws10-core, RFC 8414). */
    public static final String AS_METADATA_PATH = "/.well-known/lws-configuration";

    public String storageDescriptionIri() {
        return baseUri + storageDescriptionPath();
    }

    public String subscriptionsEndpointIri() {
        return baseUri + subscriptionsPath();
    }

    public String jwksIri() {
        return baseUri + jwksPath();
    }

    public String typeIndexEndpointIri() {
        return baseUri + typeIndexPath();
    }

    public String typeSearchEndpointIri() {
        return baseUri + typeSearchPath();
    }

    public String accessRequestsEndpointIri() {
        return baseUri + accessRequestsPath();
    }

    public String accessGrantsEndpointIri() {
        return baseUri + accessGrantsPath();
    }

    public String tokenEndpointIri() {
        return baseUri + tokenPath();
    }

    /**
     * The issuer identifier of the embedded authorization server: this storage's base URI, whose
     * metadata is therefore at {@code /.well-known/lws-configuration} (RFC 8414 section 3).
     */
    public String oauthIssuer() {
        return baseUri;
    }

    public String oauthMetadataIri() {
        return baseUri + AS_METADATA_PATH;
    }

    /** Whether the embedded authorization server issues access tokens for this storage. */
    public boolean oauthEnabled() {
        return oauthEnabled;
    }

    /** Lifetime of an access token the embedded authorization server issues. */
    public long oauthAccessTokenLifetimeSeconds() {
        return oauthAccessTokenLifetimeSeconds;
    }

    /** External authorization servers whose access tokens this storage accepts, by issuer. */
    public Set<String> oauthTrustedIssuers() {
        return oauthTrustedIssuers;
    }

    /**
     * The authorization server a {@code 401} names in its {@code as_uri}: the embedded one when it
     * is enabled, otherwise the first trusted external one, otherwise {@code null}.
     */
    public String primaryAuthorizationServer() {
        if (oauthEnabled) {
            return oauthIssuer();
        }
        return oauthTrustedIssuers.isEmpty() ? null : oauthTrustedIssuers.iterator().next();
    }

    /**
     * Whether an authentication credential — an ID token, a self-signed JWT, a SAML assertion —
     * presented to this storage directly is honoured, in addition to access tokens.
     */
    public boolean oauthAcceptCredentials() {
        return oauthAcceptCredentials;
    }

    /** Whether a notification names the agent that made the change. */
    public boolean notificationsIncludeActor() {
        return notificationsIncludeActor;
    }

    /** Whether the Access Request / Access Grant services are advertised and served. */
    public boolean accessRequestsEnabled() {
        return accessRequestsEnabled;
    }

    /** The controller's inbox for new-access-request notifications, or {@code null} if not configured. */
    public String accessControllerInbox() {
        return accessControllerInbox.isBlank() ? null : accessControllerInbox;
    }

    /** Maximum total binary-content bytes the storage will hold, or {@code <= 0} for unlimited. */
    public long quotaMaxBytes() {
        return quotaMaxBytes;
    }

    /** Maximum accepted request-body size in bytes, or {@code <= 0} for unlimited. */
    public long maxRequestBytes() {
        return maxRequestBytes;
    }

    /** Maximum serialized size of one resource's user-managed linkset metadata (finding N5). */
    public long linksetMaxBytes() {
        return linksetMaxBytes;
    }

    /** Whether an authenticated principal without Read is answered 404 rather than 403. */
    public boolean maskForbiddenAsNotFound() {
        return maskForbiddenAsNotFound;
    }

    /** Whether DPoP proofs must carry a server-issued nonce (RFC 9449 §8). */
    public boolean dpopRequireNonce() {
        return dpopRequireNonce;
    }

    /**
     * Whether plain {@code Bearer} access tokens are refused outright, so every request must be
     * DPoP-bound. A {@code cnf.jkt}-bearing token is refused under {@code Bearer} regardless of
     * this setting (RFC 9449 §7.1).
     */
    public boolean dpopRequired() {
        return dpopRequire;
    }

    /**
     * How many DPoP {@code jti} values the replay guard retains. An entry evicted because the cache
     * is full has not expired, so the proof that wrote it becomes replayable again: size this above
     * the number of DPoP requests expected within the proof acceptance window.
     */
    public int dpopJtiCacheSize() {
        return dpopJtiCacheSize;
    }

    /** How long a fetched SSI-CID subject (controlled identifier) document is reused. */
    public long ssiCidDocumentCacheSeconds() {
        return ssiCidDocumentCacheSeconds;
    }

    /** How long an SSI-CID subject document that could not be fetched is left alone before a retry. */
    public long ssiCidDocumentFailureCacheSeconds() {
        return ssiCidDocumentFailureCacheSeconds;
    }

    /** The {@code aud} values a JWT credential may carry; defaults to this storage's own IRIs. */
    public Set<String> acceptedAudiences() {
        return acceptedAudiences;
    }

    /** Whether a JWT credential must carry an {@code aud} claim naming this storage. */
    public boolean audienceRequired() {
        return audienceRequired;
    }

    /**
     * Maximum lifetime ({@code exp - iat}) accepted for a self-signed credential, in milliseconds,
     * or {@code <= 0} for unlimited. Bounds the damage from a leaked self-minted token.
     */
    public long tokenMaxLifetimeMs() {
        return tokenMaxLifetimeMs;
    }

    /** Hosts (lower-cased) a SPARQL Update {@code LOAD}/{@code SERVICE} may fetch from; empty = none. */
    public Set<String> sparqlUpdateAllowedHosts() {
        return sparqlUpdateAllowedHosts;
    }

    /** Whether auth/WAC outbound fetches refuse hosts resolving to private/loopback/metadata addresses. */
    public boolean fetchBlockPrivateAddresses() {
        return fetchBlockPrivateAddresses;
    }

    /** Hosts (lower-cased) exempt from the outbound-fetch private-address block; empty = none exempt. */
    public Set<String> fetchAllowedHosts() {
        return fetchAllowedHosts;
    }

    /** Whether notification delivery refuses inboxes resolving to private/loopback/metadata addresses. */
    public boolean webhookBlockPrivateAddresses() {
        return webhookBlockPrivateAddresses;
    }

    /** Hosts (lower-cased) permitted as notification inboxes despite the private-address block. */
    public Set<String> webhookAllowedHosts() {
        return webhookAllowedHosts;
    }

    /** Whether an unauthenticated client may create a webhook subscription. */
    public boolean subscriptionsAllowAnonymous() {
        return subscriptionsAllowAnonymous;
    }

    /** Maximum number of subscriptions one subscriber may hold. */
    public int subscriptionsMaxPerSubscriber() {
        return subscriptionsMaxPerSubscriber;
    }

    /** Maximum (and default) subscription lifetime in seconds; {@code 0} means no expiry is imposed. */
    public long subscriptionsMaxLifetimeSeconds() {
        return subscriptionsMaxLifetimeSeconds;
    }

    /** Hosts (lower-cased) whose JSON-LD {@code @context} may be fetched; empty refuses all remote contexts. */
    public Set<String> jsonLdAllowedContextHosts() {
        return jsonLdAllowedContextHosts;
    }

    /** Whether to expose an embedded Fuseki SPARQL endpoint over the local dataset (opt-in). */
    public boolean sparqlEndpointEnabled() {
        return sparqlEndpointEnabled;
    }

    public int sparqlEndpointPort() {
        return sparqlEndpointPort;
    }

    /** The dataset path of the SPARQL endpoint (e.g. {@code /lws}; query at {@code <path>/sparql}). */
    public String sparqlEndpointDataset() {
        return sparqlEndpointDataset;
    }

    /** Whether the SPARQL endpoint is query-only (no update / graph-store writes). */
    public boolean sparqlEndpointReadOnly() {
        return sparqlEndpointReadOnly;
    }

    /** Whether the SPARQL endpoint binds to loopback only (localhost). */
    public boolean sparqlEndpointLoopback() {
        return sparqlEndpointLoopback;
    }

    /**
     * The SPARQL query URL to advertise in the storage description: the configured
     * {@code public-url} if set (e.g. a reverse-proxied address), else one derived from the storage
     * base host, the endpoint port and dataset.
     */
    public String sparqlEndpointAdvertisedUrl() {
        if (!sparqlEndpointPublicUrl.isBlank()) {
            return sparqlEndpointPublicUrl;
        }
        URI base = URI.create(baseUri);
        return base.getScheme() + "://" + base.getHost() + ":" + sparqlEndpointPort
                + sparqlEndpointDataset + "/sparql";
    }

    /** Whether the Type Index / Type Search services are advertised and served (lws10-searchindex). */
    public boolean searchIndexEnabled() {
        return searchIndexEnabled;
    }

    /** Maximum number of items per Type Index / Type Search response page. */
    public int searchIndexPageSize() {
        return searchIndexPageSize;
    }

    /** Maximum number of members per container-listing page (larger listings are paginated). */
    public int containerPageSize() {
        return containerPageSize;
    }

    /** True if {@code path} addresses a server-managed system resource. */
    public boolean isSystemPath(String path) {
        return path.equals(systemPrefix) || path.startsWith(systemPrefix + "/");
    }

    /** The path prefix the management console is served from; no resource may be created under it. */
    public static final String UI_PREFIX = "/app";

    /** The path the OpenID Connect login callback is served from. */
    public static final String CALLBACK_PATH = "/callback";

    /**
     * Where the ACME HTTP-01 challenge responder is mapped when TLS certificate automation is on.
     * Reserved unconditionally: whether it is currently mapped depends on {@code lws.tls.enabled},
     * and a name that becomes shadowed the day an operator turns TLS on is a name no resource
     * should have been able to take.
     */
    public static final String ACME_CHALLENGE_PREFIX = "/.well-known/acme-challenge";

    /**
     * True if no resource may be created or replaced at {@code path} because something else already
     * owns that name.
     *
     * <p>These namespaces are reserved: the {@code .acl} and {@code .meta} suffixes, which the
     * request router diverts to the access-control and linkset handlers; the configured system
     * prefix (default {@code /.lws}); the {@code /app} and {@code /callback} trees, which the
     * console and login filters occupy; and the {@code /.well-known/acme-challenge} and
     * {@code /.well-known/lws-configuration} paths, where the ACME responder and the authorization
     * server metadata are served. The rest of {@code /.well-known/} is left to the storage — a
     * {@code did:web} owner may want its {@code did.json} there.
     *
     * <p>This must be a <em>superset</em> of what the router hides. Reserving more than is shadowed
     * costs a name nobody wants; reserving less is finding C2, where a resource created at
     * {@code /c/.acl} became the graph governing access to {@code /c/} — and finding H18, where a
     * resource created at {@code /c/x.meta} was minted at an address every HTTP method routes away
     * from, so it could never be read or deleted again.
     *
     * <p>The path is tested exactly as given, with no percent-decoding: it is the same string that
     * becomes the resource IRI, so guard and IRI cannot disagree. {@code /c/x%2Eacl} is therefore a
     * distinct, legal, reachable name — which is correct, because the router treats it as one too.
     */
    public boolean isReservedPath(String path) {
        // Anchored the same way Iris.toIri anchors it, so a caller that passes a path without the
        // leading slash is measured against the IRI it would actually mint.
        String p = (path.startsWith("/") ? path : "/" + path).toLowerCase(Locale.ROOT);
        return Iris.hasReservedSuffix(p)
                || isUnder(p, systemPrefix.toLowerCase(Locale.ROOT))
                || isUnder(p, UI_PREFIX)
                || isUnder(p, CALLBACK_PATH)
                || isUnder(p, ACME_CHALLENGE_PREFIX)
                || isUnder(p, AS_METADATA_PATH);
    }

    private static boolean isUnder(String path, String prefix) {
        return path.equals(prefix) || path.startsWith(prefix + "/");
    }

    public Set<String> ownerWebIds() {
        return ownerWebIds;
    }

    /** Open (development) mode: no owners configured, so authorization is permissive. */
    public boolean isOpenMode() {
        return ownerWebIds.isEmpty();
    }

    /**
     * Whether agents who are neither an owner nor otherwise authorized may read the storage.
     *
     * <p>Storage-wide, and always was: in owner mode this is the whole of the non-owner read policy,
     * and in WAC it decides whether the bootstrapped root ACL carries a public {@code acl:Read}. To
     * open one resource or one subtree, issue an access grant with {@code assignee: foaf:Agent}.
     */
    public boolean publicReadDefault() {
        return publicReadDefault;
    }

    /**
     * Whether development-only postures are permitted: an empty {@link #ownerWebIds()} (open mode),
     * and {@link #uiDevLoginEnabled()} on a non-loopback base URI. <b>Insecure. Development only.</b>
     */
    public boolean devOpen() {
        return devOpen;
    }

    public AccessControl accessControl() {
        return accessControl;
    }

    public boolean isWac() {
        return accessControl == AccessControl.WAC;
    }

    /** How long a successfully resolved {@code acl:agentGroup} membership set is reused. */
    public long wacGroupCacheSeconds() {
        return wacGroupCacheSeconds;
    }

    /** How long a group document that could not be resolved is left alone before a retry. */
    public long wacGroupFailureCacheSeconds() {
        return wacGroupFailureCacheSeconds;
    }

    /** How many group documents a single authorization decision may dereference. */
    public int wacMaxGroupFetchesPerDecision() {
        return wacMaxGroupFetchesPerDecision;
    }

    public RdfBackend rdfBackend() {
        return rdfBackend;
    }

    public String sparqlQueryEndpoint() {
        return sparqlQueryEndpoint;
    }

    public String sparqlUpdateEndpoint() {
        return sparqlUpdateEndpoint;
    }

    public String sparqlGspEndpoint() {
        return sparqlGspEndpoint;
    }

    /**
     * Whether the operator has acknowledged that {@code lws.sparql.mode=REMOTE} runs without
     * transactions. Startup refuses REMOTE without it; see {@link #validateRemoteBackend()}.
     */
    public boolean sparqlRemoteAcknowledged() {
        return sparqlRemoteAcknowledged;
    }

    public boolean oidcLoginEnabled() {
        return !oidcDiscoveryUri.isBlank() && !oidcClientId.isBlank();
    }

    public String oidcDiscoveryUri() {
        return oidcDiscoveryUri;
    }

    public String oidcClientId() {
        return oidcClientId;
    }

    public String oidcClientSecret() {
        return oidcClientSecret;
    }

    /**
     * Whether the Wicket UI offers a developer sign-in form that lets you act as any WebID
     * (impersonation). Insecure — for development only; defaults to {@code false}.
     */
    public boolean uiDevLoginEnabled() {
        return uiDevLogin;
    }

    /** True if SAML credential validation is configured (at least one trusted IdP certificate). */
    public boolean samlEnabled() {
        return !samlCertPaths.isEmpty();
    }

    public List<String> samlIdpCertificatePaths() {
        return samlCertPaths;
    }

    public Set<String> samlTrustedIssuers() {
        return samlTrustedIssuers;
    }

    /** Expected SAML audience, or {@code null} to skip the audience check. */
    public String samlAudience() {
        return samlAudience.isBlank() ? null : samlAudience;
    }

    /** Worker threads delivering notifications. */
    public int webhookThreads() {
        return webhookThreads;
    }

    /**
     * How many deliveries may wait for a worker before new ones are dropped. Bounded because the
     * queue used to be unbounded: a slow inbox let it grow until the heap did.
     */
    public int webhookQueueCapacity() {
        return webhookQueueCapacity;
    }

    /**
     * How many deliveries may be in flight to one inbox host at a time. Without a cap, two
     * unresponsive inboxes could occupy every worker and stall delivery for everybody else.
     */
    public int webhookMaxInFlightPerHost() {
        return webhookMaxInFlightPerHost;
    }

    public int webhookMaxAttempts() {
        return webhookMaxAttempts;
    }

    public long webhookRetryBackoffMillis() {
        return webhookRetryBackoffMillis;
    }

    public int webhookMaxConsecutiveFailures() {
        return webhookMaxConsecutiveFailures;
    }

    /** How often to purge expired subscriptions, in seconds (0 disables). */
    public long subscriptionPurgeIntervalSeconds() {
        return subscriptionPurgeIntervalSeconds;
    }

    /** Whether to trust {@code X-Forwarded-*} / {@code Forwarded} headers from a fronting proxy. */
    public boolean behindProxy() {
        return behindProxy;
    }

    /** Whether a non-HTTPS, non-loopback base URI is refused at startup. */
    public boolean requireHttps() {
        return requireHttps;
    }

    /**
     * The {@code Strict-Transport-Security} lifetime in seconds, or {@code 0} to send no header.
     * Applied only to responses that were served over TLS and only when {@link #baseUri()} is
     * {@code https}; see {@code HstsFilter}.
     */
    public long hstsMaxAgeSeconds() {
        return hstsMaxAgeSeconds;
    }

    /** Whether any cross-origin access is configured at all; when false, no CORS filter is installed. */
    public boolean corsEnabled() {
        return corsAllowsAnyOrigin || !corsAllowedOrigins.isEmpty();
    }

    /** The web origins (lower-cased) permitted to read this storage's API from a browser. */
    public Set<String> corsAllowedOrigins() {
        return corsAllowedOrigins;
    }

    /**
     * Whether {@code lws.cors.allowed-origins} contains {@code *}. Legal only because this server
     * never sends {@code Access-Control-Allow-Credentials}, and refused outright in open mode — see
     * {@link #validateCors()}.
     */
    public boolean corsAllowsAnyOrigin() {
        return corsAllowsAnyOrigin;
    }

    /** How long a browser may cache a CORS preflight result, in seconds. */
    public long corsMaxAgeSeconds() {
        return corsMaxAgeSeconds;
    }

    /** Whether the server terminates TLS itself, provisioning a certificate via ACME. */
    public boolean tlsEnabled() {
        return tlsEnabled;
    }

    /** The HTTPS listen port (when {@link #tlsEnabled()}). */
    public int tlsPort() {
        return tlsPort;
    }

    /** The HTTP listen port that serves the ACME challenge and redirects to HTTPS (when TLS is on). */
    public int tlsHttpPort() {
        return tlsHttpPort;
    }

    /** Directory holding the ACME account key, domain key, and certificate chain. */
    public Path tlsDir() {
        return tlsDir;
    }

    /** The ACME directory URL (e.g. Let's Encrypt production or staging). */
    public String acmeDirectoryUrl() {
        return acmeDirectoryUrl;
    }

    /** The domains to request a certificate for (defaults to the base-URI host). */
    public List<String> acmeDomains() {
        return acmeDomains;
    }

    /** The contact email for the ACME account, or empty. */
    public String acmeEmail() {
        return acmeEmail;
    }

    /** Whether the operator has accepted the ACME CA's terms of service. */
    public boolean acmeAcceptTos() {
        return acmeAcceptTos;
    }

    /** Renew the certificate when it is within this many days of expiry. */
    public int acmeRenewBeforeDays() {
        return acmeRenewBeforeDays;
    }

    @Override
    public String toString() {
        return "LwsConfiguration{baseUri=" + baseUri + ", dataDir=" + dataDir
                + ", rdfBackend=" + rdfBackend + ", accessControl=" + accessControl
                + ", owners=" + ownerWebIds + ", openMode=" + isOpenMode() + ", devOpen=" + devOpen
                + ", oidcLogin=" + oidcLoginEnabled() + ", behindProxy=" + behindProxy + '}';
    }
}
