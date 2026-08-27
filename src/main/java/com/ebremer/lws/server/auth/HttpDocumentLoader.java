package com.ebremer.lws.server.auth;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.riot.Lang;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.rdf.RdfFormats;
import com.ebremer.lws.server.rdf.RdfIO;

/**
 * Default {@link DocumentLoader} that dereferences a document over HTTP(S). Every request is
 * bounded and guarded:
 *
 * <ul>
 *   <li>the URL is validated against an {@link OutboundFetchPolicy} (an SSRF guard) before any
 *       connection, and <strong>again for every redirect hop</strong> — the client is built with
 *       {@link HttpClient.Redirect#NEVER} and follows {@code 3xx} responses itself precisely so
 *       that no hop escapes the policy;</li>
 *   <li>redirects are capped at {@link #MAX_REDIRECTS}, and the whole exchange — every hop
 *       together — is capped at {@link #TOTAL_BUDGET}, so a long chain of individually
 *       well-behaved responses cannot add up to minutes;</li>
 *   <li>connection, request and <em>response body</em> are time-bounded;</li>
 *   <li>the response body is capped at {@link #MAX_BODY_BYTES} to bound memory from a hostile
 *       document.</li>
 * </ul>
 *
 * @author Erich Bremer
 */
public final class HttpDocumentLoader implements DocumentLoader {

    private static final Logger log = LoggerFactory.getLogger(HttpDocumentLoader.class);

    /** Maximum document size accepted (controlled-identifier / DID documents are small). */
    private static final long MAX_BODY_BYTES = 2L * 1024 * 1024;

    /** Maximum number of {@code 3xx} hops followed; each is re-checked against the fetch policy. */
    private static final int MAX_REDIRECTS = 5;

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);

    /**
     * Ceiling on one whole {@link #fetch}: every redirect hop and every response body together.
     *
     * <p>This is the only real wall-clock bound here, and it is enforced by waiting on the
     * asynchronous exchange rather than by {@link HttpRequest.Builder#timeout}. Measured against
     * this JDK: a host that returns {@code 200 OK} at once and then emits one byte every two
     * seconds runs for the full drip under a three-second request timeout — with a streaming body
     * handler <em>and</em> with a buffering one. The request timeout stops covering the exchange
     * once the response is delivered, so it never bounds the body. {@code MAX_REDIRECTS} has the
     * same shape of gap: without a total, a chain of individually prompt hops multiplies.
     */
    private static final Duration TOTAL_BUDGET = Duration.ofSeconds(20);

    private static final String JSON_ACCEPT = "application/ld+json, application/did+json, application/json";
    private static final String RDF_ACCEPT =
            "text/turtle, application/ld+json;q=0.9, application/n-triples;q=0.8, application/rdf+xml;q=0.7";

    private final OutboundFetchPolicy fetchPolicy;
    // Redirect.NEVER is deliberate: this class follows redirects itself so that OutboundFetchPolicy
    // is applied to every hop. A client that follows them internally would let a public host
    // 30x-redirect the server to an internal or cloud-metadata address unchecked.
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(CONNECT_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public HttpDocumentLoader(OutboundFetchPolicy fetchPolicy) {
        this.fetchPolicy = fetchPolicy;
    }

    @Override
    public String load(String url) {
        Fetched fetched = fetch(url, JSON_ACCEPT);
        return fetched == null ? null : new String(fetched.body(), StandardCharsets.UTF_8);
    }

    @Override
    public Model loadRdf(String url) {
        Fetched fetched = fetch(url, RDF_ACCEPT);
        if (fetched == null) {
            return null;
        }
        Lang lang = RdfFormats.langForContentType(fetched.contentType()).orElse(Lang.TURTLE);
        try {
            return RdfIO.parse(fetched.body(), lang, fetched.finalUrl());
        } catch (RuntimeException e) {
            log.debug("Could not parse RDF document {} as {}: {}", url, lang, e.toString());
            return null;
        }
    }

    /** A retrieved document: its bytes, its declared media type, and the URL it was finally read from. */
    private record Fetched(byte[] body, String contentType, String finalUrl) {
    }

    /**
     * Retrieve {@code url}, following up to {@link #MAX_REDIRECTS} hops and re-applying the
     * outbound-fetch policy to each one. Returns {@code null} on any refusal, error or overflow.
     */
    private Fetched fetch(String url, String accept) {
        String current = url;
        long deadline = System.nanoTime() + TOTAL_BUDGET.toNanos();
        try {
            for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
                if (!fetchPolicy.permits(current)) {
                    log.debug("Refusing to load document {} (blocked by outbound-fetch policy{})",
                            current, current.equals(url) ? "" : "; reached by redirect from " + url);
                    return null;
                }
                Duration remaining = Duration.ofNanos(deadline - System.nanoTime());
                if (!remaining.isPositive()) {
                    log.debug("Document {} exceeded the {} budget; refusing", url, TOTAL_BUDGET);
                    return null;
                }
                HttpRequest request = HttpRequest.newBuilder(URI.create(current))
                        .timeout(remaining.compareTo(REQUEST_TIMEOUT) < 0 ? remaining : REQUEST_TIMEOUT)
                        .header("Accept", accept)
                        .GET()
                        .build();
                // Waited on with an explicit deadline, not just request.timeout(): cancelling the
                // exchange is what actually aborts a response body that has stopped arriving.
                CompletableFuture<HttpResponse<byte[]>> pending =
                        http.sendAsync(request, CappedBody.handler());
                HttpResponse<byte[]> response;
                try {
                    response = pending.get(remaining.toMillis(), TimeUnit.MILLISECONDS);
                } catch (TimeoutException e) {
                    pending.cancel(true); // aborts the exchange and closes the connection
                    log.debug("Document {} exceeded the {} budget; refusing", url, TOTAL_BUDGET);
                    return null;
                }
                int status = response.statusCode();
                if (status / 100 == 3) {
                    Optional<String> location = response.headers().firstValue("Location");
                    if (location.isEmpty()) {
                        log.debug("Document {} returned HTTP {} with no Location", current, status);
                        return null;
                    }
                    current = URI.create(current).resolve(location.get()).toString();
                    continue;
                }
                if (status / 100 != 2) {
                    log.debug("Document {} returned HTTP {}", current, status);
                    return null;
                }
                byte[] body = response.body();
                if (body == null) {
                    log.debug("Document {} exceeds {} bytes; refusing", current, MAX_BODY_BYTES);
                    return null;
                }
                return new Fetched(body, response.headers().firstValue("Content-Type").orElse(null), current);
            }
            log.debug("Document {} exceeded {} redirects; refusing", url, MAX_REDIRECTS);
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.debug("Interrupted loading document {}", url);
            return null;
        } catch (Exception e) {
            log.debug("Could not load document {}: {}", url, e.toString());
            return null;
        }
    }

    /**
     * Buffers a response body, giving up (and yielding {@code null}) once it passes
     * {@link #MAX_BODY_BYTES}.
     *
     * <p>Enforcing the cap in the subscriber rather than by reading a bounded prefix of a streamed
     * body is what lets the body arrive as part of the exchange, which is in turn what
     * {@link #TOTAL_BUDGET}'s deadline can cancel. It also refuses an oversize document the moment
     * it grows past the limit, without draining the rest of it.
     */
    private static final class CappedBody implements HttpResponse.BodySubscriber<byte[]> {

        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private Flow.Subscription subscription;
        private boolean overflowed;

        static HttpResponse.BodyHandler<byte[]> handler() {
            return info -> new CappedBody();
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            for (ByteBuffer item : items) {
                if (buffer.size() + item.remaining() > MAX_BODY_BYTES) {
                    overflowed = true;
                    subscription.cancel();
                    body.complete(null);
                    return;
                }
                byte[] chunk = new byte[item.remaining()];
                item.get(chunk);
                buffer.writeBytes(chunk);
            }
        }

        @Override
        public void onError(Throwable throwable) {
            body.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            body.complete(overflowed ? null : buffer.toByteArray());
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return body;
        }
    }
}
