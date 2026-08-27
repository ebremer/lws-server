package com.ebremer.lws.server.notifications;

/**
 * What happened to one delivery attempt, and therefore what to do next.
 *
 * <p>Retrying used to be outcome-blind: every non-2xx and every exception was tried
 * {@code lws.webhook.max-attempts} times with a growing sleep in between, so a {@code 404} inbox and
 * a {@code mailto:} URL that {@code HttpRequest.newBuilder} rejects outright each cost five
 * attempts and twenty seconds of a worker thread (finding M34). None of those retries could ever
 * succeed: the condition being retried was permanent.
 *
 * @author Erich Bremer
 */
enum DeliveryOutcome {

    /** 2xx. Done. */
    DELIVERED(true, false),

    /** 5xx, 429, or transient I/O — the subscriber may be back shortly. */
    RETRY(false, false),

    /**
     * A 4xx other than 429, or a request this client cannot even construct (a non-HTTP scheme).
     * Counted as a failure so a permanently broken inbox still deactivates eventually, but never
     * retried: nothing about the next attempt would differ.
     */
    PERMANENT(false, false),

    /** 410 Gone: the subscriber has said this inbox is finished. Deactivate now, do not retry. */
    GONE(false, true);

    private final boolean success;
    private final boolean deactivate;

    DeliveryOutcome(boolean success, boolean deactivate) {
        this.success = success;
        this.deactivate = deactivate;
    }

    boolean isSuccess() {
        return success;
    }

    boolean isRetryable() {
        return this == RETRY;
    }

    boolean shouldDeactivate() {
        return deactivate;
    }

    /** Classify an HTTP status code. */
    static DeliveryOutcome forStatus(int status) {
        if (status >= 200 && status < 300) {
            return DELIVERED;
        }
        if (status == 410) {
            return GONE;
        }
        if (status == 429 || status >= 500) {
            return RETRY;
        }
        return PERMANENT;
    }
}
