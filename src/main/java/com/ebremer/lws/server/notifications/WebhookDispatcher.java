package com.ebremer.lws.server.notifications;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * Delivers notifications to subscriber inboxes over HTTP, asynchronously. Each request is
 * signed with RFC 9421 HTTP Message Signatures. Failed deliveries are retried with linear
 * backoff; persistent failures are reported to the {@link SubscriptionService}, which
 * deactivates the subscription after too many consecutive failures.
 *
 * @author Erich Bremer
 */
public final class WebhookDispatcher implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(WebhookDispatcher.class);

    private final WebhookKeys keys;
    private final SubscriptionService subscriptions;
    private final LwsConfiguration config;
    private final HttpClient http;
    private final ExecutorService executor;

    public WebhookDispatcher(WebhookKeys keys, SubscriptionService subscriptions, LwsConfiguration config) {
        this.keys = keys;
        this.subscriptions = subscriptions;
        this.config = config;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        this.executor = Executors.newFixedThreadPool(2, daemonThreads());
    }

    /** Queue a signed delivery to a subscription's inbox. */
    public void deliver(Subscription subscription, byte[] body, String contentType) {
        executor.submit(() -> deliverSync(subscription, body, contentType));
    }

    /**
     * Queue a best-effort signed delivery of a one-off notification to an arbitrary inbox (e.g. the
     * inbox on an access request/grant). Unlike {@link #deliver}, it keeps no subscription state.
     */
    public void deliverTo(String inboxUrl, byte[] body, String contentType) {
        executor.submit(() -> {
            URI inbox;
            try {
                inbox = URI.create(inboxUrl);
            } catch (RuntimeException e) {
                log.warn("Invalid notification inbox {}", inboxUrl);
                return;
            }
            deliverWithRetry(inbox, body, contentType, inboxUrl);
        });
    }

    private void deliverSync(Subscription subscription, byte[] body, String contentType) {
        URI inbox;
        try {
            inbox = URI.create(subscription.inbox());
        } catch (RuntimeException e) {
            log.warn("Subscription {} has an invalid inbox {}", subscription.id(), subscription.inbox());
            subscriptions.recordDelivery(subscription.id(), false);
            return;
        }
        subscriptions.recordDelivery(subscription.id(),
                deliverWithRetry(inbox, body, contentType, "subscription " + subscription.id()));
    }

    /** Attempt delivery with linear backoff; returns whether a 2xx was received. */
    private boolean deliverWithRetry(URI inbox, byte[] body, String contentType, String label) {
        int maxAttempts = Math.max(1, config.webhookMaxAttempts());
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                if (sendSigned(inbox, body, contentType)) {
                    return true;
                }
                log.warn("Delivery to {} returned non-2xx (attempt {}/{})", label, attempt, maxAttempts);
            } catch (Exception e) {
                log.warn("Delivery to {} failed (attempt {}/{}): {}", label, attempt, maxAttempts, e.toString());
            }
            if (attempt < maxAttempts) {
                try {
                    Thread.sleep(config.webhookRetryBackoffMillis() * attempt);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        return false;
    }

    private boolean sendSigned(URI inbox, byte[] body, String contentType) throws Exception {
        long created = System.currentTimeMillis() / 1000L;
        HttpMessageSignatures.SignatureHeaders sig =
                HttpMessageSignatures.sign("POST", inbox, contentType, body, keys, created);
        HttpRequest request = HttpRequest.newBuilder(inbox)
                .timeout(Duration.ofSeconds(15))
                .header("Content-Type", contentType)
                .header("Content-Digest", sig.contentDigest())
                .header("Signature-Input", sig.signatureInput())
                .header("Signature", sig.signature())
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        HttpResponse<Void> response = http.send(request, HttpResponse.BodyHandlers.discarding());
        return response.statusCode() >= 200 && response.statusCode() < 300;
    }

    @Override
    public void close() {
        executor.shutdown();
    }

    private static ThreadFactory daemonThreads() {
        AtomicInteger n = new AtomicInteger();
        return r -> {
            Thread t = new Thread(r, "lws-webhook-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }
}
