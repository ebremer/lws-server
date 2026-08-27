package com.ebremer.lws.server;

import java.time.Clock;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.pac4j.core.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.auth.AudiencePolicy;
import com.ebremer.lws.server.auth.AuthenticationFilter;
import com.ebremer.lws.server.auth.DefaultAccessPolicy;
import com.ebremer.lws.server.auth.DidKeyValidator;
import com.ebremer.lws.server.auth.DocumentLoader;
import com.ebremer.lws.server.auth.DpopNonceService;
import com.ebremer.lws.server.auth.DpopValidator;
import com.ebremer.lws.server.auth.GrantAuthorizer;
import com.ebremer.lws.server.auth.HttpDocumentLoader;
import com.ebremer.lws.server.auth.LegacyAclMigration;
import com.ebremer.lws.server.auth.LwsCredentialValidator;
import com.ebremer.lws.server.auth.LwsOpenIdValidator;
import com.ebremer.lws.server.auth.OutboundFetchPolicy;
import com.ebremer.lws.server.auth.OwnerAuthorizer;
import com.ebremer.lws.server.auth.SamlValidator;
import com.ebremer.lws.server.auth.SsiCidValidator;
import com.ebremer.lws.server.auth.Pac4jSupport;
import com.ebremer.lws.server.auth.WacAclService;
import java.util.function.Predicate;
import com.ebremer.lws.server.core.AclMode;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.vocab.LWS;
import com.ebremer.lws.server.core.AccessService;
import com.ebremer.lws.server.core.Authorizer;
import com.ebremer.lws.server.core.LinksetService;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.core.SearchIndexService;
import com.ebremer.lws.server.core.StorageDescriptionService;
import com.ebremer.lws.server.notifications.NotificationEmitter;
import com.ebremer.lws.server.notifications.SubscriptionService;
import com.ebremer.lws.server.notifications.WebhookDispatcher;
import com.ebremer.lws.server.notifications.WebhookKeys;
import com.ebremer.lws.server.rdf.FusekiSparqlServer;
import com.ebremer.lws.server.rdf.JsonLdSecurity;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.rdf.RemoteSparqlRdfStore;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.BinaryStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;

/**
 * The application's object graph, wired with plain Java and no framework annotations.
 *
 * <p>This is the seam that keeps the Spring footprint tiny: Spring Boot (or, in future, a bare
 * Eclipse Jetty launcher) only has to construct one of these and register its servlets and
 * filters. Nothing below this class knows or cares which container hosts it.
 *
 * @author Erich Bremer
 */
public final class LwsComponents implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(LwsComponents.class);

    private final LwsConfiguration config;
    private final RdfStore rdfStore;
    private final BinaryStore binaryStore;
    private final WacAclService aclService; // nullable: only when access-control = WAC
    private final ResourceService resourceService;
    private final StorageDescriptionService storageDescriptionService;
    private final SearchIndexService searchIndexService;
    private final LinksetService linksetService;
    private final AccessService accessService;
    private final LwsCredentialValidator credentialValidator;
    private final DpopValidator dpopValidator;
    private final WebhookKeys webhookKeys;
    private final SubscriptionService subscriptionService;
    private final WebhookDispatcher webhookDispatcher;
    private final NotificationEmitter notificationEmitter;
    private final ScheduledExecutorService purgeScheduler;
    private final FusekiSparqlServer sparqlServer; // nullable: only when the SPARQL endpoint is enabled
    private final Config pac4jConfig; // nullable: only when UI OIDC login is configured
    private final Clock clock;

    private LwsComponents(LwsConfiguration config) {
        this.config = config;
        this.clock = Clock.systemUTC();

        // Before anything can parse RDF: widen the default (refuse-all) JSON-LD @context loader to
        // whatever the operator has allow-listed. A client-supplied @context would otherwise make
        // the server fetch a URL of the document's choosing.
        JsonLdSecurity.install(config.jsonLdAllowedContextHosts());

        this.rdfStore = config.rdfBackend() == LwsConfiguration.RdfBackend.TDB2
                ? new Tdb2RdfStore(config.tdb2Dir())
                : new RemoteSparqlRdfStore(config.sparqlQueryEndpoint(), config.sparqlUpdateEndpoint(),
                        config.sparqlGspEndpoint());
        // ...and now that the store exists, tell the context loader how to find out whether a write
        // transaction is open, so it can refuse to fetch under the writer lock (finding N1). This is
        // the same rule WacAclService applies to an acl:agentGroup document, for the same reason.
        JsonLdSecurity.setTransactionProbe(this.rdfStore::inUnitOfWork);
        this.binaryStore = new FileSystemBinaryStore(config.blobDir());

        ResourceRegistry registry = new ResourceRegistry();
        Authorizer baseAuthorizer;
        if (config.isWac()) {
            this.aclService = new WacAclService(rdfStore, config,
                    new HttpDocumentLoader(OutboundFetchPolicy.from(config)));
            baseAuthorizer = this.aclService;
        } else {
            this.aclService = null;
            baseAuthorizer = new OwnerAuthorizer(rdfStore, registry, new DefaultAccessPolicy(config));
        }
        // Access grants augment whichever base model is configured (owner or WAC): a granted action
        // is permitted even if the base denies it, so grants work — and revoke — without ACL edits.
        // Notification delivery posts to client-supplied inbox URLs; one policy governs every such
        // target, applied at document/subscription creation and again before each delivery attempt.
        OutboundFetchPolicy deliveryPolicy = OutboundFetchPolicy.forDelivery(config);
        // The issuer question goes to the BASE authorizer, never to `authorizer`. `authorizer` is
        // what calls AccessService.grants, so routing back through it would put grant evaluation
        // inside grant evaluation. It terminates because neither OwnerAuthorizer nor WacAclService
        // holds a reference to AccessService, GrantAuthorizer or ResourceService — both are fully
        // constructed above, before accessService exists, so they cannot.
        Authorizer base = baseAuthorizer;
        Predicate<String> stillAController = webId -> webId != null && !LWS.FOAF_AGENT.equals(webId)
                && base.allows(new LwsPrincipal(webId, null, null), config.storageRootIri(), AclMode.CONTROL);
        this.accessService = new AccessService(rdfStore, config, registry, deliveryPolicy::permits,
                stillAController);
        Authorizer authorizer = config.accessRequestsEnabled()
                ? new GrantAuthorizer(baseAuthorizer, accessService, config, clock) : baseAuthorizer;
        this.resourceService = new ResourceService(rdfStore, binaryStore, registry, authorizer, config, clock);
        this.storageDescriptionService = new StorageDescriptionService(config);
        this.searchIndexService = new SearchIndexService(rdfStore, authorizer);
        if (config.searchIndexEnabled()) {
            // Maintain the search service's derived type index incrementally as resources change.
            this.resourceService.addEventListener(searchIndexService);
        }
        this.linksetService = new LinksetService(rdfStore, resourceService, config);
        this.resourceService.addDeleteCleanup(linksetService); // drop a resource's metadata with the delete
        if (config.searchIndexEnabled()) {
            // A client may declare its resource's types in that resource's own metadata, which
            // lws10-searchindex treats as the preferred source; the index reads them, and is told
            // when they change. Wired here rather than in either constructor because the two are
            // mutually dependent.
            this.searchIndexService.setLinksets(linksetService);
            this.linksetService.setMetadataListener(searchIndexService::onMetadataChanged);
        }

        SamlValidator saml = config.samlEnabled()
                ? new SamlValidator(SamlValidator.loadTrustedKeys(config.samlIdpCertificatePaths()),
                        config.samlTrustedIssuers(), config.samlAudience())
                : null;
        OutboundFetchPolicy fetchPolicy = OutboundFetchPolicy.from(config);
        DocumentLoader documentLoader = new HttpDocumentLoader(fetchPolicy);
        AudiencePolicy audiencePolicy = AudiencePolicy.from(config);
        long tokenMaxLifetimeMs = config.tokenMaxLifetimeMs();
        this.credentialValidator = new LwsCredentialValidator(
                new LwsOpenIdValidator(fetchPolicy, documentLoader, audiencePolicy),
                new SsiCidValidator(documentLoader, audiencePolicy, tokenMaxLifetimeMs,
                        config.ssiCidDocumentCacheSeconds(), config.ssiCidDocumentFailureCacheSeconds()),
                new DidKeyValidator(audiencePolicy, tokenMaxLifetimeMs), saml);
        this.dpopValidator = new DpopValidator(
                config.dpopRequireNonce() ? new DpopNonceService() : null, config.dpopJtiCacheSize());

        this.webhookKeys = new WebhookKeys(config.keysDir());
        this.subscriptionService =
                new SubscriptionService(rdfStore, resourceService, config, clock, deliveryPolicy);
        this.webhookDispatcher =
                new WebhookDispatcher(webhookKeys, subscriptionService, config, deliveryPolicy);
        this.notificationEmitter = new NotificationEmitter(subscriptionService, webhookDispatcher, resourceService, config);
        this.resourceService.addEventListener(notificationEmitter);
        // Who may be told about a delete has to be decided before the delete, not after it (H19).
        this.resourceService.setDeleteAudience(notificationEmitter::subscribersAllowedToKnow);

        this.pac4jConfig = Pac4jSupport.buildConfig(config);

        this.resourceService.ensureStorageRoot();
        if (aclService != null) {
            resourceService.addDeleteCleanup(aclService); // drop a resource's ACL with the delete (H24)
            // Before the root ACL is bootstrapped, so that a store whose root ACL was overwritten
            // through the old client-reachable address gets it rebuilt from lws.owners here.
            LegacyAclMigration.migrate(rdfStore, config, registry);
            aclService.bootstrapRootAcl();
        } else {
            // Nothing reads ACLs in owner mode, so nothing is moved — but say what is there, since
            // switching lws.access-control to WAC would bring it to life.
            LegacyAclMigration.report(rdfStore, config, registry);
        }

        if (config.accessRequestsEnabled()) {
            // A grant is invisible in lws.owners and in every ACL, so an operator inheriting a
            // storage has no other way to notice one. Inert grants are named separately because
            // they are the ones a lockdown was supposed to have removed and did not.
            AccessService.Census census = accessService.census();
            if (census.total() > 0) {
                log.warn("{} access grant(s) stored; {} were issued by an agent that no longer "
                        + "controls this storage and authorize nothing. Review them at {}",
                        census.total(), census.inert(), config.accessGrantsEndpointIri());
            }
        }

        this.purgeScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "lws-subscription-purge");
            t.setDaemon(true);
            return t;
        });
        long purgeInterval = config.subscriptionPurgeIntervalSeconds();
        if (purgeInterval > 0) {
            purgeScheduler.scheduleAtFixedRate(() -> {
                try {
                    int removed = subscriptionService.purgeExpired(clock.instant());
                    if (removed > 0) {
                        log.info("Purged {} expired subscription(s)", removed);
                    }
                } catch (RuntimeException e) {
                    log.warn("Subscription purge failed: {}", e.toString());
                }
            }, purgeInterval, purgeInterval, TimeUnit.SECONDS);
        }

        if (config.sparqlEndpointEnabled() && rdfStore instanceof Tdb2RdfStore tdb) {
            this.sparqlServer = new FusekiSparqlServer(tdb.dataset(), config);
            this.sparqlServer.start();
        } else {
            this.sparqlServer = null;
            if (config.sparqlEndpointEnabled()) {
                log.warn("SPARQL endpoint requested but the RDF backend is REMOTE; "
                        + "query the remote SPARQL service directly instead.");
            }
        }

        log.info("LWS components ready: {}", config);
        if (config.rdfBackend() == LwsConfiguration.RdfBackend.REMOTE) {
            // Startup already refused this mode unless it was asked for; say at every start what was
            // agreed to, because the guarantees it drops are invisible until they are needed (M16).
            log.warn("Metadata store is REMOTE SPARQL, which has no transactions "
                    + "(lws.sparql.remote.accept-no-transactions=true): conditional writes are not a "
                    + "compare-and-swap, a delete does not erase the resource's ACL and linkset "
                    + "atomically with it, and the storage quota is advisory.");
        }
        if (config.isOpenMode() && !config.isWac()) {
            log.warn("Running in OPEN mode (no owners configured): all reads and writes are permitted. "
                    + "Set 'lws.owners' to secure the storage.");
        }
    }

    public static LwsComponents create(LwsConfiguration config) {
        return new LwsComponents(config);
    }

    public LwsConfiguration config() {
        return config;
    }

    public ResourceService resourceService() {
        return resourceService;
    }

    /** The WAC ACL service, or {@code null} when access-control is owner-based. */
    public WacAclService aclService() {
        return aclService;
    }

    public StorageDescriptionService storageDescriptionService() {
        return storageDescriptionService;
    }

    public SearchIndexService searchIndexService() {
        return searchIndexService;
    }

    public LinksetService linksetService() {
        return linksetService;
    }

    public AccessService accessService() {
        return accessService;
    }

    public NotificationEmitter notificationEmitter() {
        return notificationEmitter;
    }

    public LwsCredentialValidator credentialValidator() {
        return credentialValidator;
    }

    public AuthenticationFilter authenticationFilter() {
        return new AuthenticationFilter(credentialValidator, dpopValidator, config);
    }

    public WebhookKeys webhookKeys() {
        return webhookKeys;
    }

    public SubscriptionService subscriptionService() {
        return subscriptionService;
    }

    public Config pac4jConfig() {
        return pac4jConfig;
    }

    public Clock clock() {
        return clock;
    }

    @Override
    /**
     * Shut every component down, independently.
     *
     * <p>Each step is guarded because they used to run as a straight sequence: the first one to throw
     * skipped every step after it, and the one most likely to throw — the optional SPARQL server —
     * sat in front of the two that matter most, the delivery pool and the TDB2 store. A store left
     * open holds its lock file, which is what turns "shutdown logged a stack trace" into "the next
     * start fails".
     */
    public void close() {
        closeQuietly("subscription purge scheduler", purgeScheduler::shutdownNow);
        if (sparqlServer != null) {
            closeQuietly("SPARQL endpoint", sparqlServer::close);
        }
        closeQuietly("webhook dispatcher", webhookDispatcher::close);
        closeQuietly("RDF store", rdfStore::close);
        log.info("LWS components closed");
    }

    private static void closeQuietly(String what, Runnable shutdown) {
        try {
            shutdown.run();
        } catch (RuntimeException e) {
            log.warn("Failed to shut down the {}: {}", what, e.toString());
        }
    }
}
