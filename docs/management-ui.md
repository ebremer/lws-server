---
title: Management UI
nav_order: 14
---

# Management UI

An [Apache Wicket](https://wicket.apache.org/) console is mounted at `/app/` (home `/app/browse`).
Signed in with sufficient permission, you can:

- browse the storage hierarchy;
- create resources (typing RDF/text, or uploading a binary file);
- edit RDF;
- replace a binary resource's bytes by upload;
- delete resources; and
- edit each resource's WAC ACL.

Actions run **in-process as the signed-in principal**, so authorization is enforced exactly as for
the [HTTP API](http-api.md) — and the UI only offers actions the current principal is allowed to
perform.

## Signing in

Sign in at `/app/login` by:

- pasting an OpenID Connect **ID token** (validated just like the HTTP API);
- **OpenID Connect single sign-on** — a browser redirect via pac4j, shown when an OIDC client is
  configured (`lws.oidc.discovery-uri` / `.client-id` / `.client-secret`; see
  [below](#single-sign-on-with-an-openid-provider)); or
- when `lws.ui.dev-login=true`, a **developer sign-in** that lets you act as any WebID
  (impersonation — **development / administration only**). The server refuses to start with it on a
  non-loopback `lws.base-uri` unless `lws.dev.open=true`, and refuses it per request off-loopback or
  behind a proxy.

## Single sign-on with an OpenID provider

The console signs in through the provider's browser login (authorization-code flow) when all three
settings are present:

```properties
lws.oidc.discovery-uri=https://idp.example/realms/example/.well-known/openid-configuration
lws.oidc.client-id=https://storage.example/app
lws.oidc.client-secret=...
```

What the provider's client needs:

- **Confidential, with a secret.** The console authenticates to the token endpoint with
  `client_secret_basic`, whatever else the provider advertises.
- **Redirect URI `<lws.base-uri>/callback`, allowing a query string.** The console sends
  `<base-uri>/callback?client_name=OidcClient`, so register `<base-uri>/callback*` (Keycloak) or the
  exact URL with the query. Under a path prefix that is, for example, `https://example.org/lws/callback*`.
- **The WebID as `sub`.** The ID token's subject becomes the signed-in principal and is what
  `lws.owners` and ACLs are matched against. With Keycloak, lws-authn's `lws-webid-sub-mapper` does
  this from a user attribute.
- **`aud` containing the client ID**, which providers do by default.

After the provider's login the console applies the suite's trust check, as the API does: it fetches
the subject's WebID/CID document and requires that the subject itself names the token's issuer as a
service of type `lws:OpenIdProvider`. A user whose profile does not name the provider is refused with
a message saying so. The console's client ID does not have to be a URI, because the console does not
use the token exchange, but a URI keeps it consistent with the storage's other clients.

## Browser security

- **Cross-site request forgery.** Wicket has no CSRF token and its stateful callback URLs are
  guessable, so the console registers Wicket's `ResourceIsolationRequestCycleListener` (Fetch
  Metadata, with an `Origin` fallback), and every destructive action is a `POST` rather than a link.
- **Session cookie.** `HttpOnly` and `SameSite=Strict`, and `Secure` when the request came over TLS
  (directly, or through a proxy with `lws.behind-proxy=true`).
- **CORS.** `/app` and the OIDC `/callback` are excluded from cross-origin access whatever
  `lws.cors.allowed-origins` says; the console is same-origin only.

{: .note }
> Under a path prefix (see [Deployment](deployment.md#under-a-path-prefix)) the console is at
> `<base-uri>/app/`. Its redirects keep the prefix, even though the proxy strips it before the server
> sees the request, and its session cookie is scoped to the prefix, so other sites on the same host never receive it.
