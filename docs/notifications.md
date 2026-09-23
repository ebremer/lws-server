---
title: Notifications
nav_order: 9
---

# Notifications
{: .no_toc }

1. TOC
{:toc}

The server delivers change notifications as signed webhooks: the notification data model of
[LWS Core](https://w3c.github.io/lws-protocol/lws10-core/#notifications), delivered by the
[webhook suite](https://w3c.github.io/lws-protocol/lws10-notifications-webhook/).

## Subscribe

Discover support in the [storage description](http-api.md#discovery--the-storage-description): a
`NotificationService` with a `serviceEndpoint` and `subscriptionType: ["WebhookSubscription"]`.
Create a subscription with an authenticated `application/lws+json` `POST` to `/.lws/subscriptions`:

```json
{
  "@context": ["https://www.w3.org/ns/lws/v1"],
  "type": "WebhookSubscription",
  "topic": ["http://localhost:8080/some/container/"],
  "inbox": "https://example.org/inbox",
  "expires": "2026-12-31T00:00:00Z"
}
```

The answer is `201` with the subscription's `Location` and an `application/lws+json` body carrying
`type`, `subscription` (its URL) and the `expires` the server applied. `GET` on the endpoint lists
the caller's subscriptions as an LWS container (all of them for a storage controller); `GET` on a
subscription returns its state and `DELETE` cancels it. RDF is still available by asking for it.

- **Container topics are recursive** — a subscription to a container covers everything beneath it.
- The server enforces that the subscriber may **read** every topic, and will not deliver a
  notification for a resource the subscriber cannot read — including on **delete**, where the
  decision is captured before the resource is removed, so a container's subscriber learns nothing
  about a private child that was deleted. Authorization is checked at delivery time, with no request
  context (the writer's `Origin` and `LWS-Purpose` do not apply to the subscriber), so a later
  revocation takes effect.
- `expires` is optional but bounded (`lws.subscriptions.max-lifetime-seconds`); a background task
  purges expired subscriptions on the `lws.subscription.purge-interval-seconds` schedule.
- Creation requires an authenticated subscriber unless `lws.subscriptions.allow-anonymous=true`, is
  capped per subscriber (`lws.subscriptions.max-per-subscriber`), must declare a JSON media type
  (`415` otherwise) and may name at most 64 topics.
- The `inbox` is an outbound fetch the client chose, so it is guarded: inboxes resolving to loopback,
  private, link-local or cloud-metadata addresses are refused (`400` at creation, and re-checked
  before every delivery) unless their host is allow-listed under `lws.webhook.*`.

## Delivery

On each change the server `POST`s an `application/lws+json` notification in the lws10-core data model
to the subscription's `inbox`:

```json
{ "@context": ["https://www.w3.org/ns/lws/v1", "https://www.w3.org/ns/activitystreams"],
  "type": "Notification",
  "storage": "http://localhost:8080/",
  "activity": { "id": "urn:uuid:…", "type": ["Create"],
                "object": { "id": "http://localhost:8080/some/container/new", "type": ["DataResource"] },
                "target": "http://localhost:8080/some/container/",
                "published": "2026-09-22T10:30:00.000Z" } }
```

`type` values are arrays (`Create` / `Update` / `Delete`); `target` names the container a `Create`
added to and `origin` the one a `Delete` removed from. The `actor` is omitted unless
`lws.notifications.include-actor=true`, as the core's privacy considerations advise.

Each delivery is signed with [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message
Signatures covering `@method @scheme @authority @path content-type content-digest`, with `created` and
`keyid` parameters. The **`keyid`** is the id of the signing key's verification method in the storage
description — `<storage URI>#<thumbprint>`. A subscriber strips the fragment, dereferences the storage
URI (asking for `application/lws+cid`), finds the `JsonWebKey` in `verificationMethod`, and checks
both the RFC 9421 signature and the RFC 9530 `Content-Digest` against the body. The same key is still
published as a JWKS at `/.lws/jwks`.

Delivery outcomes are classified rather than retried blindly: `5xx`, `429` and transient I/O errors
are retried up to `lws.webhook.max-attempts` with scheduled back-off; a `410 Gone` deactivates the
subscription immediately; any other `4xx` counts as a failure and is not retried. A subscription is
deactivated after `lws.webhook.max-consecutive-failures` consecutive failures. The delivery pool is
bounded by worker count, queue depth and per-host in-flight deliveries, so one unresponsive
subscriber cannot hold a worker or grow the queue without limit. Failure counts are kept server-side
and not exposed in the subscription's representation.

## Access-event notifications

[Access requests and grants](authorization.md#access-requests--grants) emit the same kind of signed
notification, in the core data model, on creation, delivered to the document's own `inbox`, the configured controller
inbox (for a new request), and a linked request's inbox (for a grant that references it).
