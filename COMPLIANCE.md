# LWS Protocol Compliance: lws-server

**Date:** 2026-07-09  
**Scope:** Whether `lws-server` correctly implements LWS Core and the other LWS protocol suites (aside from known security/concurrency bugs).  
**Related:** `REVIEW-lws-server.md` (code review findings)

## Short answer

**Yes** — aside from the known bugs and a few claim/ops gaps, `lws-server` is a real implementation of **LWS Core + vocab + all four auth suites + notifications + search/type-index** (and access requests/grants as part of core). It is **not** a full formal “conformance suite pass” against a frozen Recommendation, because **LWS Core’s published HTML is still incomplete**, and this project follows the **Operations/ source + LDP/Solid conventions** where the draft is silent.

---

## What “the suites” are

From the [LWS protocol set](https://w3c.github.io/lws-protocol/):

| Spec | Role in `lws-server` |
|------|----------------------|
| **lws10-core** | Storage, resources, containers, CRUD, discovery, linksets, access requests/grants |
| **lws10-vocab** | `https://www.w3.org/ns/lws#` terms |
| **authn-*** (×4) | Credential validation at the resource server |
| **lws10-notifications** | Webhook subscriptions + signed delivery |
| **lws10-searchindex** | Type Index + Type Search |

Extras (useful, **not** separate LWS “suites”): WAC, DPoP, ACME/TLS, optional Fuseki, quotas, Wicket UI.

---

## LWS Core — substantially yes

Core’s rendered Editor’s Draft is still largely skeletal; normative detail lives in operations text and LDP/Solid practice. Against that practical bar, the server implements the main model and HTTP surface.

### Present and aligned

| Area | What the code does |
|------|--------------------|
| **Resource model** | Storage root, containment, `Container` / `DataResource`, parent hierarchy |
| **Create** | `POST` into container (Slug, `Link: rel="type"`), `PUT` at exact path |
| **Read** | `GET`/`HEAD`, content negotiation, authz-filtered container listings |
| **Update** | Conditional `PUT` (428 without `If-Match`, 412 stale); `PATCH` SPARQL Update / merge-patch / JSON Patch |
| **Delete** | Resource delete; non-empty container → 409 unless `Depth: infinity` recursive delete |
| **Containers** | Canonical `application/lws+json` listing (`type`, `id`, `totalItems`, `items` with `mediaType`/`size`/`modified`) + pagination |
| **Auxiliary metadata** | `*.meta` linkset (`application/linkset+json`), `rel="up"` / `rel="linkset"`, conditional meta writes, `Prefer: set-linkset` |
| **Discovery** | Storage description (`Storage` + `service` / `capability`), self-advertised `StorageDescription` |
| **Conditionals / HTTP** | ETags, `Last-Modified` / `If-Modified-Since`, byte ranges (206/416), `Accept-Ranges` |
| **Errors** | RFC 9457 `application/problem+json` |
| **Access requests & grants** | Container-like endpoints, ODRL-ish docs, `GrantAuthorizer`, revocable grants, fail-closed unknown constraints |
| **AuthZ** | Owner mode or WAC; grants layered on top |

Conformance-style coverage lives in `OperationsConformanceTest` (lws+json containers, ranges, conditional PUT, linksets, storage description, recursive delete, SPARQL `LOAD`/`SERVICE` guard, problem+json, etc.).

### Gaps / softness (beyond security bugs)

| Gap | Nature |
|-----|--------|
| **Spec incompleteness** | No locked Rec; README admits flux and LDP/Solid fill-ins |
| **Optimistic concurrency** | If-Match checked outside write TX (known bug); PATCH/DELETE not as strict as PUT |
| **Blob vs RDF TX** | Binary store not rolled back with TDB (known bug) |
| **Full “metadata resource” story** | Linksets are solid; broader “metadata resource” draft sections are still TBD in the ED |
| **Authorization profile** | LWS doesn’t mandate WAC; OWNER vs WAC is an implementation choice (reasonable) |

**Core verdict:** For an interoperable LWS *storage* as the drafts + Operations describe today — **yes, correctly oriented and largely complete**, with concurrency/atomicity bugs and draft-driven incompleteness, not a missing product surface.

---

## LWS Vocabulary — yes

`vocab/LWS.java` (and AS/LDP/ACL companions) mint the expected terms: `Storage`, `Container`, `DataResource`, notification/search/access types, services, etc. Servlets and services emit `application/lws+json` with the LWS context. This is real vocab use, not a rename layer.

---

## Authentication suites (as RP) — yes, with known gaps

Server-side: four validators + `LwsCredentialValidator` routing.

| Suite | Protocol algorithm | Caveats (non-bug + bugs) |
|-------|--------------------|---------------------------|
| **OpenID** | CID → OpenIdProvider → discovery → JWT | `aud` not enforced; `azp` optional |
| **SSI CID** | `sub==iss==client_id` → CID key by kid | `aud` not required |
| **SAML** | OOB IdP certs → signature → NameID | wrapping bug; soft Conditions |
| **did:key** | Decode key from id → JWT | `aud` not required |

**Verdict:** Suite *shapes* are correct; claim strictness and SAML wrapping are the weak points.

---

## Notifications — yes (strong)

Matches the notifications proposal’s main MUSTs:

| Requirement | Implementation |
|-------------|----------------|
| Advertise `NotificationService` + `WebhookSubscription` | Storage description |
| POST subscription with `type` / `topic` / `inbox` | `SubscriptionService` + servlet |
| Create-time read auth on every topic | Enforced |
| Delivery-time re-check of read auth | `NotificationEmitter.authorizedToReceive` |
| Container topic recursive | `Subscription.covers` |
| Envelope `Notification` + AS2 Create/Update/Delete | Built on resource events |
| RFC 9421 components (`@method`, `@scheme`, `@authority`, `@path`, `content-type`, `content-digest`) + `created`/`keyid` | `HttpMessageSignatures` |
| Key in storage description | Webhook Ed25519 keys + storage description |
| List / GET / DELETE subscriptions | `SubscriptionServlet` |
| expires, retry, deactivate after failures | Config + dispatcher |

**Gaps (ops/security more than “wrong suite”):**

- Spec expects **authenticated** subscription create; with default **public-read**, anonymous subscribe can still pass topic auth.
- **Webhook SSRF** (inbox not under outbound policy) — security bug, not a missing envelope model.
- Actor inclusion policy is an implementation detail (spec prefers omit by default).

---

## Search & Type Index — yes (strong)

| Requirement | Implementation |
|-------------|----------------|
| Advertise `TypeIndexService` / `TypeSearchService` | Storage description (when enabled) |
| Type Index GET → paginated `TypeIndex` | `SearchIndexServlet` + service |
| Type Search GET **and** POST, CNF (`type` OR groups, AND across params) | Implemented |
| Authz filter live; `totalItems` client-specific | Explicit in code + `SearchIndexAuthzTest` |
| Don’t index structural/protocol relations as free discovery oracle | Admin graph separated; unindexed relations → empty results |
| Reject over-complex filters (400), not silent narrowing | Clause/value bounds |
| `Cache-Control: private, no-store` | Servlet |

**Soft gaps:** Type derivation leans on **server structural types + RDF content `rdf:type`**, not primarily client `Link: rel="type"` (spec *SHOULD* use Link headers; *MAY* parse content — still valid). Eventual-consistency of the index is acknowledged; in practice events are sync on the write path.

---

## Access requests & grants (core section) — yes

- Advertised services, create/list/delete style endpoints  
- Grants enforced via `GrantAuthorizer`  
- No `Control` via grant; fail-closed unknown constraints  
- Notifications to inboxes on create (when configured)  

Remaining issues are scale (load all grants) and notification SSRF on arbitrary inboxes — not “feature missing.”

---

## Scorecard

| Suite / area | Correct core model? | Completeness | Main residual issues |
|--------------|---------------------|--------------|----------------------|
| **LWS Core** | Yes | High for practical ops | Spec flux; If-Match TOCTOU; blob/RDF atomicity; uneven conditionals |
| **Vocab** | Yes | High | — |
| **Auth ×4** | Yes | High shape / medium claim-strict | `aud`/`azp`/`iat`; SAML wrapping on server |
| **Notifications** | Yes | High | Public-topic anonymous subscribe; webhook SSRF |
| **Search/Type Index** | Yes | High | Derivation source bias; unbounded in-memory type index at scale |
| **Access grants** | Yes | High | Perf under many grants; inbox SSRF |

---

## Bottom line

**Yes — `lws-server` correctly implements LWS Core and the other LWS suites in the sense that matters for a real storage:** resource/containment CRUD, storage description, linksets, the four auth credential shapes, webhook notifications with signed delivery and dual-time authz, type index/search with live authz filtering, and access requests/grants.

What it is **not**:

1. A **formal Rec-level conformance certificate** (core ED is incomplete; behavior fills gaps with LDP/Solid).  
2. **Bug-free** (especially SSRF on webhooks, SAML wrapping, concurrency/atomicity).  
3. **Claim-maximal** on every MUST in auth drafts (`aud`, etc.).

### Ship posture (protocol fidelity)

**Ship with fixes** — architecture and suite coverage are sound; production multi-tenant needs the security/concurrency fixes, not a rewrite of the protocol engine.

### Suggested next step

A checklist of MUST statements vs code for core Operations only (create/read/update/delete + linkset + storage description), line by line — that is where “conformance” will get sharper as the Editor’s Draft fills in.
