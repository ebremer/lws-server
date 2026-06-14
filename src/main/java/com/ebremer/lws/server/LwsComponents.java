package com.ebremer.lws.server;

import java.time.Clock;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.shiro.mgt.SecurityManager;
import org.pac4j.core.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.auth.AuthenticationFilter;
import com.ebremer.lws.server.auth.DefaultAccessPolicy;
import com.ebremer.lws.server.auth.DidKeyValidator;
import com.ebremer.lws.server.auth.DocumentLoader;
import com.ebremer.lws.server.auth.DpopNonceService;
import com.ebremer.lws.server.auth.DpopValidator;
import com.ebremer.lws.server.auth.GrantAuthorizer;
import com.ebremer.lws.server.auth.HttpDocumentLoader;
import com.ebremer.lws.server.auth.LwsCredentialValidator;
import com.ebremer.lws.server.auth.LwsOpenIdValidator;
import com.ebremer.lws.server.auth.OutboundFetchPolicy;
import com.ebremer.lws.server.auth.OwnerAuthorizer;
import com.ebremer.lws.server.auth.SamlValidator;
import com.ebremer.lws.server.auth.SsiCidValidator;
import com.ebremer.lws.server.auth.Pac4jSupport;
import com.ebremer.lws.server.auth.ShiroSupport;
import com.ebremer.lws.server.auth.WacAclService;
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
    private final SecurityManager securityManager;
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

        this.rdfStore = config.rdfBackend() == LwsConfiguration.RdfBackend.TDB2
                ? new Tdb2RdfStore(config.tdb2Dir())
                : new RemoteSparqlRdfStore(config.sparqlQueryEndpoint(), config.sparqlUpdateEndpoint(),
                        config.sparqlGspEndpoint());
        this.binaryStore = new FileSystemBinaryStore(config.blobDir());

        ResourceRegistry registry = new ResourceRegistry();
        Authorizer baseAuthorizer;
        if (config.isWac()) {
            this.aclService = new WacAclService(rdfStore, config);
            baseAuthorizer = this.aclService;
        } else {
            this.aclService = null;
            baseAuthorizer = new OwnerAuthorizer(rdfStore, registry, new DefaultAccessPolicy(config));
        }
        // Access grants augment whichever base model is configured (owner or WAC): a granted action
        // is permitted even if the base denies it, so grants work — and revoke — without ACL edits.
        this.accessService = new AccessService(rdfStore, config, registry);
        Authorizer authorizer = config.accessRequestsEnabled()
                ? new GrantAuthorizer(baseAuthorizer, accessService, clock) : baseAuthorizer;
        this.resourceService = new ResourceService(rdfStore, binaryStore, registry, authorizer, config, clock);
        this.storageDescriptionService = new StorageDescriptionService(config);
        this.searchIndexService = new SearchIndexService(rdfStore, authorizer);
        if (config.searchIndexEnabled()) {
            // Maintain the search service's derived type index incrementally as resources change.
            this.resourceService.addEventListener(searchIndexService);
        }
        this.linksetService = new LinksetService(rdfStore, resourceService, config);
        this.resourceService.addEventListener(linksetService); // drop a resource's metadata on delete

        SamlValidator saml = config.samlEnabled()
                ? new SamlValidator(SamlValidator.loadTrustedKeys(config.samlIdpCertificatePaths()),
                        config.samlTrustedIssuers(), config.samlAudience())
                : null;
        OutboundFetchPolicy fetchPolicy = OutboundFetchPolicy.from(config);
        DocumentLoader documentLoader = new HttpDocumentLoader(fetchPolicy);
        this.credentialValidator = new LwsCredentialValidator(new LwsOpenIdValidator(fetchPolicy),
                new SsiCidValidator(documentLoader), new DidKeyValidator(), saml);
        this.dpopValidator = new DpopValidator(
                config.dpopRequireNonce() ? new DpopNonceService() : null);
        this.securityManager = ShiroSupport.createSecurityManager(config);

        this.webhookKeys = new WebhookKeys(config.keysDir());
        this.subscriptionService = new SubscriptionService(rdfStore, resourceService, config, clock);
        this.webhookDispatcher = new WebhookDispatcher(webhookKeys, subscriptionService, config);
        this.notificationEmitter = new NotificationEmitter(subscriptionService, webhookDispatcher, resourceService, config);
        this.resourceService.addEventListener(notificationEmitter);

        this.pac4jConfig = Pac4jSupport.buildConfig(config);

        this.resourceService.ensureStorageRoot();
        if (aclService != null) {
            resourceService.addEventListener(aclService); // drop a resource's ACL when it is deleted
            aclService.bootstrapRootAcl();
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

    public SecurityManager securityManager() {
        return securityManager;
    }

    public AuthenticationFilter authenticationFilter() {
        return new AuthenticationFilter(credentialValidator, dpopValidator, config, securityManager);
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
    public void close() {
        purgeScheduler.shutdownNow();
        if (sparqlServer != null) {
            sparqlServer.close();
        }
        webhookDispatcher.close();
        rdfStore.close();
        log.info("LWS components closed");
    }
}
