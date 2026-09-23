---
title: Notifications
nav_order: 9
---

# Notifications
{: .no_toc }

1. TOC
{:toc}

The server delivers change notifications as signed webhooks, per the
[LWS Notifications](https://w3c.github.io/lws-protocol/lws10-notifications/) suite.

## Subscribe

Discover support in the [storage description](http-api.md#discovery--the-storage-description): a
`NotificationService` with a `serviceEndpoint` and a `WebhookSubscription` type. Create a subscription
with an authenticated `POST` to `/.lws/subscriptions`:

```json
{
  "type": "WebhookSubscription",
  "topic": ["http://localhost:8080/some/container/"],
  "inbox": "https://example.org/inbox",
  "expires": "2026-12-31T00:00:00Z"
}
```

- **Container topics are recursive** — a subscription to a container covers everything beneath it.
- The server enforces that the subscriber may **read** every topic, and will not deliver a
  notification for a resource the subscriber cannot read. Authorization is checked at delivery time,
  so a later revocation takes effect.
- `expires` is optional; a background task purges expired subscriptions on the
  `lws.subscription.purge-interval-seconds` schedule.

## Delivery

On each change the server `POST`s a JSON-LD `lws:Notification` (wrapping an Activity Streams 2.0
`Create` / `Update` / `Delete`) to the subscription's `inbox`, signed with
[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signatures covering
`@method @scheme @authority @path content-type content-digest`, with `created` and `keyid` parameters.

A subscriber verifies the delivery by fetching the server's **public signing key**, published as a
JWKS at `/.lws/jwks`, and checking both the RFC 9421 signature and the RFC 9530 `Content-Digest`
against the body — exactly what the end-to-end test does.

Delivery is retried up to `lws.webhook.max-attempts`; a subscription is deactivated after
`lws.webhook.max-consecutive-failures` consecutive failures.

## Access-event notifications

[Access requests and grants](authorization.md#access-requests--grants) emit the same kind of signed
`lws:Notification` on creation, delivered to the document's own `inbox`, the configured controller
inbox (for a new request), and a linked request's inbox (for a grant that references it).
