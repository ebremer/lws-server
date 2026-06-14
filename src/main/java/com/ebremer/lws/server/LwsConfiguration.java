package com.ebremer.lws.server;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
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
    private final AccessControl accessControl;

    private final RdfBackend rdfBackend;
    private final String sparqlQueryEndpoint;
    private final String sparqlUpdateEndpoint;
    private final String sparqlGspEndpoint;

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
    private final boolean dpopRequireNonce;

    // SPARQL Update: hosts that LOAD/SERVICE may fetch from (empty = none; SSRF guard).
    private final Set<String> sparqlUpdateAllowedHosts;

    // Outbound-fetch SSRF guard for auth (WebID/OIDC) and WAC agentGroup dereferences.
    private final boolean fetchBlockPrivateAddresses;
    private final Set<String> fetchAllowedHosts;

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
        this.port = baseUriParsed.getPort() > 0 ? baseUriParsed.getPort() : 8080;
        this.dataDir = getPath(p, "lws.data-dir", "lws-data");
        this.systemPrefix = "/" + get(p, "lws.system-prefix", ".lws").replaceAll("^/+", "").replaceAll("/+$", "");
        this.ownerWebIds = parseSet(get(p, "lws.owners", ""));
        this.publicReadDefault = getBoolean(p, "lws.public-read", true);
        this.accessControl = getEnum(p, "lws.access-control", AccessControl.class, AccessControl.OWNER);

        this.rdfBackend = getEnum(p, "lws.sparql.mode", RdfBackend.class, RdfBackend.TDB2);
        this.sparqlQueryEndpoint = get(p, "lws.sparql.query", "");
        this.sparqlUpdateEndpoint = get(p, "lws.sparql.update", "");
        this.sparqlGspEndpoint = get(p, "lws.sparql.gsp", "");

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
        this.subscriptionPurgeIntervalSeconds =
                getLong(p, "lws.subscription.purge-interval-seconds", 3600, 0, Long.MAX_VALUE);

        this.searchIndexEnabled = getBoolean(p, "lws.search-index.enabled", true);
        this.searchIndexPageSize = getInt(p, "lws.search-index.page-size", 100, 1, Integer.MAX_VALUE);
        this.containerPageSize = getInt(p, "lws.container.page-size", 1000, 1, Integer.MAX_VALUE);
        this.accessRequestsEnabled = getBoolean(p, "lws.access-requests.enabled", true);
        this.accessControllerInbox = get(p, "lws.access-requests.controller-inbox", "");
        this.quotaMaxBytes = getLong(p, "lws.quota.max-bytes", 0, 0, Long.MAX_VALUE);
        this.dpopRequireNonce = getBoolean(p, "lws.dpop.require-nonce", false);
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

        this.sparqlEndpointEnabled = getBoolean(p, "lws.sparql.endpoint.enabled", false);
        this.sparqlEndpointPort = getInt(p, "lws.sparql.endpoint.port", 3030, 1, 65535);
        this.sparqlEndpointDataset = "/" + get(p, "lws.sparql.endpoint.dataset", "lws")
                .replaceAll("^/+", "").replaceAll("/+$", "");
        this.sparqlEndpointReadOnly = getBoolean(p, "lws.sparql.endpoint.read-only", true);
        this.sparqlEndpointLoopback = getBoolean(p, "lws.sparql.endpoint.loopback", true);
        this.sparqlEndpointPublicUrl = get(p, "lws.sparql.endpoint.public-url", "");

        this.behindProxy = getBoolean(p, "lws.behind-proxy", false);
        this.requireHttps = getBoolean(p, "lws.require-https", false);
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
        String host = URI.create(baseUri).getHost();
        if (host == null) {
            return false;
        }
        host = host.toLowerCase();
        return host.equals("localhost") || host.startsWith("127.") || host.contains("::1");
    }

    /** Load configuration from the standard sources. */
    public static LwsConfiguration load() {
        Properties p = new Properties();
        // classpath:lws.properties
        try (InputStream in = LwsConfiguration.class.getClassLoader().getResourceAsStream("lws.properties")) {
            if (in != null) {
                p.load(in);
            }
        } catch (IOException ignored) {
            // optional
        }
        // ./lws.properties
        Path file = Path.of("lws.properties");
        if (Files.isRegularFile(file)) {
            try (InputStream in = Files.newInputStream(file)) {
                p.load(in);
            } catch (IOException ignored) {
                // optional
            }
        }
        // -Dlws.* system properties win
        System.getProperties().stringPropertyNames().stream()
                .filter(k -> k.startsWith("lws."))
                .forEach(k -> p.setProperty(k, System.getProperty(k)));
        return new LwsConfiguration(p);
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

    public int port() {
        return port;
    }

    /** The IRI of the storage root container. */
    public String storageRootIri() {
        return baseUri + "/";
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

    /** Whether DPoP proofs must carry a server-issued nonce (RFC 9449 §8). */
    public boolean dpopRequireNonce() {
        return dpopRequireNonce;
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

    public Set<String> ownerWebIds() {
        return ownerWebIds;
    }

    /** Open (development) mode: no owners configured, so authorization is permissive. */
    public boolean isOpenMode() {
        return ownerWebIds.isEmpty();
    }

    public boolean publicReadDefault() {
        return publicReadDefault;
    }

    public AccessControl accessControl() {
        return accessControl;
    }

    public boolean isWac() {
        return accessControl == AccessControl.WAC;
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
                + ", owners=" + ownerWebIds + ", openMode=" + isOpenMode()
                + ", oidcLogin=" + oidcLoginEnabled() + ", behindProxy=" + behindProxy + '}';
    }
}
