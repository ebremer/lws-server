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
  configured (`lws.oidc.discovery-uri` / `.client-id` / `.client-secret`); or
- when `lws.ui.dev-login=true`, a **developer sign-in** that lets you act as any WebID
  (impersonation — **development / administration only**).
