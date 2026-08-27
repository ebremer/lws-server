package com.ebremer.lws.server.rdf;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.Set;
import java.util.function.BooleanSupplier;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdErrorCode;
import com.apicatalog.jsonld.JsonLdOptions;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import org.apache.jena.riot.RIOT;
import org.apache.jena.riot.lang.LangJSONLD11;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Locks down JSON-LD {@code @context} resolution.
 *
 * <p>Jena hands JSON-LD parsing to Titanium with a stock {@code JsonLdOptions}, whose default
 * document loader will dereference {@code http}, {@code https} <em>and</em> {@code file} URLs. Since
 * a client-supplied body chooses its own {@code @context}, that turns every RDF write into a
 * server-side request forgery primitive and a local-file read — completely bypassing
 * {@code OutboundFetchPolicy}, which never sees these fetches.
 *
 * <p>This installs a loader that refuses every remote context by default. Storing user data does not
 * require them: an inline {@code @context} object works unchanged. An operator who does need a
 * specific published vocabulary can allow its host through {@code lws.jsonld.allowed-context-hosts},
 * and those fetches are then bounded (https only, size-capped, time-bounded, no redirect following)
 * — and refused outright while a store transaction is open, for the reason on
 * {@link #setTransactionProbe}.
 *
 * <p>The default is installed from {@link RdfIO}'s static initializer, so it is in force for any
 * code path that parses RDF, whether or not the full server was wired up.
 *
 * @author Erich Bremer
 */
public final class JsonLdSecurity {

    private static final Logger log = LoggerFactory.getLogger(JsonLdSecurity.class);

    /** Contexts are small; this bounds memory from a hostile or runaway document. */
    private static final long MAX_CONTEXT_BYTES = 512L * 1024;

    /**
     * Whether {@link #install} has ever been called explicitly.
     *
     * <p>This exists because of a real bug, and removing it re-opens it. {@code RdfIO}'s static
     * initializer calls {@link #installDefault()}, and a static initializer runs on first
     * <em>use</em> of the class — which, in the assembled server, is <em>after</em>
     * {@code LwsComponents} has already installed the operator's allow-list, because nothing touches
     * {@code RdfIO} until the storage root is ensured. Measured: the options object installed by
     * {@code install(Set.of("ctx.example"))} was silently replaced by the refuse-all default on the
     * first call into {@code RdfIO}, so {@code lws.jsonld.allowed-context-hosts} was a documented
     * configuration key that did nothing at all. The default may only ever be installed when no
     * explicit policy has been set; an explicit {@link #install} always wins, in either order.
     */
    private static volatile boolean explicitlyInstalled;

    /**
     * Answers "is this thread inside a store transaction right now?". Never null.
     *
     * <p>Set by the wiring once the store exists. Until then it answers {@code false}, which is
     * correct: with no store there is no transaction to be inside.
     */
    private static volatile BooleanSupplier inUnitOfWork = () -> false;

    private JsonLdSecurity() {
    }

    /**
     * Refuse every remote {@code @context} — unless a policy has already been installed explicitly.
     * This is the default posture, and it must not downgrade an operator's configuration.
     */
    public static synchronized void installDefault() {
        if (explicitlyInstalled) {
            return;
        }
        apply(Set.of());
    }

    /**
     * Permit remote {@code @context} documents only from {@code allowedHosts} (lower-cased, https
     * only). An empty set refuses all of them.
     */
    public static synchronized void install(Set<String> allowedHosts) {
        explicitlyInstalled = true;
        apply(allowedHosts);
        if (!allowedHosts.isEmpty()) {
            log.info("JSON-LD remote contexts permitted from {}", allowedHosts);
        }
    }

    /**
     * Tell the loader how to find out whether a store transaction is open on the calling thread.
     *
     * <p>An RDF write parses its body <em>inside</em> the write transaction — the base IRI a POST
     * resolves against is only chosen in there, by {@code chooseName} — and the store admits a
     * single writer for the whole storage. So a context fetch from in there holds that writer lock
     * for as long as the remote host cares to take, stalling every other write in the server. That
     * is finding H16's harm, reached by a path H16 did not cover (finding N1).
     *
     * <p>Refused rather than bounded, and rather than warmed up beforehand. A tighter timeout still
     * holds the lock; and pre-fetching the body's contexts before the transaction opens would put a
     * network fetch, at a URL chosen by the request body, <em>before</em> the authorization check —
     * handing an anonymous client a fetch primitive it does not have today. The honest trade is that
     * a remote {@code @context} is available on the paths that parse outside a transaction (an ACL
     * write, a fetched WebID or group document, the console) and not on the resource-write path.
     */
    public static void setTransactionProbe(BooleanSupplier probe) {
        inUnitOfWork = probe == null ? () -> false : probe;
    }

    /**
     * Whether a store transaction is open on this thread.
     *
     * <p>A probe that fails — most plausibly one left pointing at a store that has since been closed
     * — is read as "no transaction". That is the truthful answer for a closed store, and this guard
     * bounds how long the writer lock is held rather than deciding what may be fetched: the
     * allow-list above is the security control, and it has already run by the time this is asked.
     */
    private static boolean insideTransaction() {
        try {
            return inUnitOfWork.getAsBoolean();
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static void apply(Set<String> allowedHosts) {
        JsonLdOptions options = new JsonLdOptions();
        options.setDocumentLoader(new GuardedContextLoader(allowedHosts));
        RIOT.getContext().set(LangJSONLD11.JSONLD_OPTIONS, options);
    }

    private static final class GuardedContextLoader implements DocumentLoader {

        private final Set<String> allowedHosts;
        private final HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        GuardedContextLoader(Set<String> allowedHosts) {
            this.allowedHosts = Set.copyOf(allowedHosts);
        }

        @Override
        public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
            String host = url.getHost();
            boolean permitted = host != null
                    && "https".equalsIgnoreCase(url.getScheme())
                    && allowedHosts.contains(host.toLowerCase(Locale.ROOT));
            if (!permitted) {
                log.debug("Refusing to dereference JSON-LD context {}", url);
                throw new JsonLdError(JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED,
                        "Remote JSON-LD contexts are not permitted: " + url
                                + " (see lws.jsonld.allowed-context-hosts)");
            }
            if (insideTransaction()) {
                // The same refusal WacAclService makes for a group document, for the same reason.
                log.warn("Refusing to dereference JSON-LD context {} while a store transaction is "
                        + "open; a remote @context cannot be resolved on the resource-write path", url);
                throw new JsonLdError(JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED,
                        "A remote JSON-LD @context cannot be resolved while storing a resource: "
                                + url + ". Inline the @context object, or use a context this "
                                + "storage has already resolved outside a write.");
            }
            try {
                HttpRequest request = HttpRequest.newBuilder(url)
                        .timeout(Duration.ofSeconds(10))
                        .header("Accept", "application/ld+json, application/json")
                        .GET()
                        .build();
                HttpResponse<InputStream> response =
                        http.send(request, HttpResponse.BodyHandlers.ofInputStream());
                if (response.statusCode() / 100 != 2) {
                    throw new JsonLdError(JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED,
                            "Context " + url + " returned HTTP " + response.statusCode());
                }
                try (InputStream in = response.body()) {
                    byte[] body = in.readNBytes((int) MAX_CONTEXT_BYTES + 1);
                    if (body.length > MAX_CONTEXT_BYTES) {
                        throw new JsonLdError(JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED,
                                "Context " + url + " exceeds " + MAX_CONTEXT_BYTES + " bytes");
                    }
                    JsonDocument document = JsonDocument.of(new java.io.ByteArrayInputStream(body));
                    // Titanium resolves relative IRIs inside a fetched context against the
                    // document's own URL, and without this it has none.
                    document.setDocumentUrl(url);
                    return document;
                }
            } catch (JsonLdError e) {
                throw e;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new JsonLdError(JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED,
                        "Interrupted loading context " + url);
            } catch (Exception e) {
                throw new JsonLdError(JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED,
                        "Could not load context " + url + ": " + e);
            }
        }
    }
}
