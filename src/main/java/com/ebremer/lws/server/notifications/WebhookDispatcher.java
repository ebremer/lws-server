package com.ebremer.lws.server.notifications;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.OutboundFetchPolicy;

/**
 * Delivers notifications to subscriber inboxes over HTTP, asynchronously and signed with RFC 9421
 * HTTP Message Signatures.
 *
 * <p>Inbox URLs are client-supplied, so every delivery target is checked against an
 * {@link OutboundFetchPolicy} ({@code lws.webhook.*}) before any request is made.
 *
 * <p>The pool is bounded in three directions, because a subscriber this server delivers to is a
 * party it does not control (findings M33 and M34):
 * <ul>
 *   <li>a <strong>bounded queue</strong> — it was unbounded, so a slow inbox let pending deliveries
 *       accumulate until the heap did;</li>
 *   <li>a <strong>per-host in-flight cap</strong> — two slowloris inboxes could otherwise occupy
 *       every worker and stall notifications for every other subscriber;</li>
 *   <li>a <strong>scheduled retry</strong> rather than {@code Thread.sleep} — backing off used to
 *       hold the worker, so one item could own a thread for the whole of
 *       {@code max-attempts × backoff} (about 95 seconds on the shipped defaults) while doing
 *       nothing.</li>
 * </ul>
 * Work refused by either bound is dropped and logged rather than queued indefinitely; a dropped
 * delivery counts as a failed one, so a subscriber whose inbox is persistently unreachable still
 * deactivates.
 *
 * <p>Retries are classified rather than blind: see {@link DeliveryOutcome}.
 *
 * @author Erich Bremer
 */
public final class WebhookDispatcher implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(WebhookDispatcher.class);

    private final WebhookKeys keys;
    private final SubscriptionService subscriptions;
    private final LwsConfiguration config;
    private final OutboundFetchPolicy deliveryPolicy;
    private final HttpClient http;
    private final ThreadPoolExecutor deliveries;
    private final ScheduledExecutorService retries;
    private final ConcurrentMap<String, AtomicInteger> inFlight = new ConcurrentHashMap<>();

    public WebhookDispatcher(WebhookKeys keys, SubscriptionService subscriptions, LwsConfiguration config) {
        this(keys, subscriptions, config, OutboundFetchPolicy.forDelivery(config));
    }

    public WebhookDispatcher(WebhookKeys keys, SubscriptionService subscriptions, LwsConfiguration config,
            OutboundFetchPolicy deliveryPolicy) {
        this.keys = keys;
        this.subscriptions = subscriptions;
        this.config = config;
        this.deliveryPolicy = deliveryPolicy;
        // Redirect.NEVER (the JDK default): an inbox that 30x-redirects must not carry the delivery
        // to an address the policy refused.
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        this.deliveries = new ThreadPoolExecutor(config.webhookThreads(), config.webhookThreads(),
                0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(config.webhookQueueCapacity()),
                daemonThreads("lws-webhook-"));
        this.retries = Executors.newSingleThreadScheduledExecutor(daemonThreads("lws-webhook-retry-"));
    }

    /**
     * Whether {@code inbox} may be delivered to. Inbox URLs come straight from client-submitted
     * JSON (a subscription's {@code inbox}, or the {@code inbox} on an access request/grant), so
     * without this the server is an authenticated-on-demand SSRF primitive: anything it can reach
     * on its own network can be POSTed at, and the delivery outcome leaks whether it answered.
     */
    public boolean permits(String inboxUrl) {
        return inboxUrl != null && deliveryPolicy.permits(inboxUrl);
    }

    /** Queue a signed delivery to a subscription's inbox. */
    public void deliver(Subscription subscription, byte[] body, String contentType) {
        submit(new Delivery(subscription.inbox(), body, contentType,
                "subscription " + subscription.id(), subscription.id()), 1);
    }

    /**
     * Queue a best-effort signed delivery of a one-off notification to an arbitrary inbox (e.g. the
     * inbox on an access request/grant). Unlike {@link #deliver}, it keeps no subscription state.
     */
    public void deliverTo(String inboxUrl, byte[] body, String contentType) {
        submit(new Delivery(inboxUrl, body, contentType, String.valueOf(inboxUrl), null), 1);
    }

    /** One delivery in flight: what to send, where, and what to report about it afterwards. */
    private record Delivery(String inbox, byte[] body, String contentType, String label, String subscriptionId) {
    }

    private void submit(Delivery delivery, int attempt) {
        String host = hostOf(delivery.inbox());
        if (!reserve(host)) {
            log.warn("Dropping delivery to {}: already {} in flight to {} "
                            + "(lws.webhook.max-in-flight-per-host)",
                    delivery.label(), config.webhookMaxInFlightPerHost(), host);
            finish(delivery, DeliveryOutcome.RETRY);
            return;
        }
        try {
            deliveries.execute(() -> {
                try {
                    attempt(delivery, attempt);
                } finally {
                    release(host);
                }
            });
        } catch (RejectedExecutionException e) {
            release(host);
            log.warn("Dropping delivery to {}: the delivery queue is full ({} waiting) "
                            + "(lws.webhook.queue-capacity)",
                    delivery.label(), config.webhookQueueCapacity());
            finish(delivery, DeliveryOutcome.RETRY);
        }
    }

    private void attempt(Delivery delivery, int attempt) {
        URI inbox = httpTarget(delivery);
        if (inbox == null) {
            finish(delivery, DeliveryOutcome.PERMANENT);
            return;
        }
        // Re-checked at every attempt as well as at creation time: the policy resolves DNS, so a
        // host that was public when the inbox was accepted may not be now.
        if (!permits(delivery.inbox())) {
            log.warn("Refusing delivery to {}: blocked by the delivery policy", delivery.label());
            finish(delivery, DeliveryOutcome.PERMANENT);
            return;
        }
        DeliveryOutcome outcome = sendOnce(inbox, delivery);
        int maxAttempts = Math.max(1, config.webhookMaxAttempts());
        if (outcome.isRetryable() && attempt < maxAttempts) {
            long delay = config.webhookRetryBackoffMillis() * attempt;
            try {
                // Hand the wait to the scheduler and let this worker go; sleeping here is what let
                // one unresponsive subscriber own a thread for a minute and a half.
                retries.schedule(() -> submit(delivery, attempt + 1), delay, TimeUnit.MILLISECONDS);
                return;
            } catch (RejectedExecutionException e) {
                log.debug("Not retrying delivery to {}: dispatcher is shutting down", delivery.label());
            }
        }
        finish(delivery, outcome);
    }

    /** The delivery target, or {@code null} if this is not something this client can POST to. */
    private URI httpTarget(Delivery delivery) {
        URI inbox;
        try {
            inbox = URI.create(delivery.inbox());
        } catch (RuntimeException e) {
            log.warn("Invalid notification inbox {}", delivery.inbox());
            return null;
        }
        String scheme = inbox.getScheme() == null ? "" : inbox.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            // URI.create accepts mailto: and much else that HttpRequest.newBuilder then throws on.
            // Retrying that five times was five identical IllegalArgumentExceptions (M34).
            log.warn("Refusing delivery to {}: {} is not an HTTP inbox", delivery.label(), delivery.inbox());
            return null;
        }
        return inbox;
    }

    private DeliveryOutcome sendOnce(URI inbox, Delivery delivery) {
        try {
            long created = System.currentTimeMillis() / 1000L;
            HttpMessageSignatures.SignatureHeaders sig = HttpMessageSignatures.sign(
                    "POST", inbox, delivery.contentType(), delivery.body(), keys,
                    config.storageIri() + "#" + keys.keyId(), created);
            HttpRequest request = HttpRequest.newBuilder(inbox)
                    .timeout(Duration.ofSeconds(15))
                    .header("Content-Type", delivery.contentType())
                    .header("Content-Digest", sig.contentDigest())
                    .header("Signature-Input", sig.signatureInput())
                    .header("Signature", sig.signature())
                    .POST(HttpRequest.BodyPublishers.ofByteArray(delivery.body()))
                    .build();
            HttpResponse<Void> response = http.send(request, HttpResponse.BodyHandlers.discarding());
            DeliveryOutcome outcome = DeliveryOutcome.forStatus(response.statusCode());
            if (outcome != DeliveryOutcome.DELIVERED) {
                log.warn("Delivery to {} answered {} ({})", delivery.label(), response.statusCode(), outcome);
            }
            return outcome;
        } catch (IllegalArgumentException e) {
            log.warn("Delivery to {} is not a request this client can make: {}", delivery.label(), e.toString());
            return DeliveryOutcome.PERMANENT;
        } catch (IOException e) {
            log.warn("Delivery to {} failed: {}", delivery.label(), e.toString());
            return DeliveryOutcome.RETRY;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return DeliveryOutcome.PERMANENT;
        }
    }

    /** Record the outcome against the subscription, if this delivery belongs to one. */
    private void finish(Delivery delivery, DeliveryOutcome outcome) {
        if (delivery.subscriptionId() == null) {
            return; // a one-off delivery keeps no state
        }
        if (outcome.shouldDeactivate()) {
            log.info("Deactivating subscription {}: its inbox answered 410 Gone", delivery.subscriptionId());
            subscriptions.deactivate(delivery.subscriptionId());
            return;
        }
        subscriptions.recordDelivery(delivery.subscriptionId(), outcome.isSuccess());
    }

    private boolean reserve(String host) {
        AtomicInteger count = inFlight.computeIfAbsent(host, h -> new AtomicInteger());
        int max = config.webhookMaxInFlightPerHost();
        while (true) {
            int current = count.get();
            if (current >= max) {
                return false;
            }
            if (count.compareAndSet(current, current + 1)) {
                return true;
            }
        }
    }

    private void release(String host) {
        AtomicInteger count = inFlight.get(host);
        if (count != null && count.decrementAndGet() <= 0) {
            // Drop the counter so the map does not grow one entry per host ever delivered to.
            inFlight.remove(host, count);
        }
    }

    private static String hostOf(String inbox) {
        try {
            String host = URI.create(inbox).getHost();
            return host == null ? String.valueOf(inbox) : host.toLowerCase(Locale.ROOT);
        } catch (RuntimeException e) {
            return String.valueOf(inbox);
        }
    }

    @Override
    public void close() {
        retries.shutdownNow();
        deliveries.shutdown();
    }

    private static ThreadFactory daemonThreads(String prefix) {
        AtomicInteger n = new AtomicInteger();
        return r -> {
            Thread t = new Thread(r, prefix + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }
}
