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
| **lws10-notifications** | Webhook subscriptions + signed delivery (RFC 9421 `@authority` normalized; delete notifications authorized against the deleted resource, not its parent) |
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
| **Update** | Conditional `PUT` (428 without `If-Match`, 412 stale, compare-and-swap inside the write transaction, enforced in the service so the console cannot bypass it); `PATCH` SPARQL Update on RDF (single-graph only), merge-patch / JSON Patch on JSON and linksets |
| **Delete** | Resource delete; non-empty container → 409 unless `Depth: infinity` recursive delete |
| **Containers** | Canonical `application/lws+json` listing (`type`, `id`, `totalItems`, `items` with `mediaType`/`size`/`modified`) + pagination |
| **Auxiliary metadata** | `*.meta` linkset (`application/linkset+json`), `rel="up"` / `rel="linkset"`, conditional meta writes, `Prefer: set-linkset` |
| **Discovery** | Storage description (`Storage` + `service` / `capability`), self-advertised `StorageDescription` |
| **Conditionals / HTTP** | ETags, `Last-Modified` / `If-Modified-Since`, byte ranges (206/416), `Accept-Ranges` |
| **Errors** | RFC 9457 `application/problem+json` |
| **Access requests & grants** | Container-like endpoints, ODRL-ish docs, `GrantAuthorizer`, revocable grants, fail-closed unknown constraints |
| **AuthZ** | Owner mode or WAC; grants layered on top |

Conformance-style coverage lives in `OperationsConformanceTest` (lws+json containers, ranges, conditional PUT, linksets, storage description, recursive delete, SPARQL `LOAD`/`SERVICE` guard, problem+json, etc.), with the concurrency semantics of those conditionals in `ConditionalWriteTest` and delete atomicity in `DeleteAtomicityTest`.

### Gaps / softness (beyond security bugs)

| Gap | Nature |
|-----|--------|
| **Spec incompleteness** | No locked Rec; README admits flux and LDP/Solid fill-ins |
| **Optimistic concurrency** | `If-Match` is compared inside the write transaction on PUT/PATCH/DELETE, on linkset writes and on ACL writes (H23/M18/prior-13). **PUT and PATCH require a precondition**; DELETE does not, deliberately — it is not an update and there is no lost state after one. `If-None-Match: *` on PUT is create-only (L28). An entity-tag names a *representation*, so the five RDF serialisations of one resource carry five tags; a write may be conditioned on any of them (M21) |
| **Blob vs RDF TX** | Resolved: every write goes to a fresh opaque blob key and cleanup is deferred until the transaction commits or aborts (H13) |
| **Merge Patch over RDF** | Deliberate departure: RFC 7386 merge patch is supported on JSON resources and linksets but **refused with `415` on RDF resources**, because applying it through the JSON-LD representation destroyed multi-subject graphs (H21). SPARQL Update is the RDF patch path. Strict-conformance deployments that need merge-patch on RDF would have to normalize the `{"@graph":[…]}` shape first — now safe to revisit, since `RdfIO.parse` refuses named-graph data instead of dropping it |
| **Full “metadata resource” story** | Linksets are solid; broader “metadata resource” draft sections are still TBD in the ED |
| **Authorization profile** | LWS doesn’t mandate WAC; OWNER vs WAC is an implementation choice (reasonable) |

**Since this was written**, the P2 remediation closed the conformance gaps this document had been
describing as soft: all four authentication suites are advertised (only OpenID was), the RDF and
`application/lws+json` renderings of the storage description are derived from one document (the RDF
one had been dropping every capability's detail), `Link: rel="type"` is accepted as a type source,
`POST` to a data resource answers `405` rather than `409`, and a type search requires a type clause.
Cross-origin access exists at all: there was no `Access-Control-*` header anywhere, which made the
whole browser-client story — and `acl:origin`, which the WAC engine implements — unreachable. It is
off until `lws.cors.allowed-origins` names an origin, and never sends `Allow-Credentials`.

**Core verdict:** For an interoperable LWS *storage* as the drafts + Operations describe today — **yes, correctly oriented and largely complete**, with draft-driven incompleteness rather than a missing product surface. The concurrency and atomicity bugs this row used to name are closed: conditional writes are a compare-and-swap under the writer lock, and a resource, its content, its ACL and its linkset are deleted in one transaction.

---

## LWS Vocabulary — yes

`vocab/LWS.java` (and AS/LDP/ACL companions) mint the expected terms: `Storage`, `Container`, `DataResource`, notification/search/access types, services, etc. Servlets and services emit `application/lws+json` with the LWS context. This is real vocab use, not a rename layer.

---

## Authentication suites (as RP) — yes, with known gaps

Server-side: four validators + `LwsCredentialValidator` routing.

| Suite | Protocol algorithm | Caveats (non-bug + bugs) |
|-------|--------------------|---------------------------|
| **OpenID** | CID → subject-anchored OpenIdProvider → discovery → JWT | `aud` enforced against `lws.audience`; `azp` informational (surfaced as the principal's client id, consumed by ODRL `client` constraints); the console login applies the same subject-trusts-issuer check |
| **SSI CID** | `sub==iss==client_id` → CID key by kid | `aud` enforced; lifetime capped by `lws.token.max-lifetime-seconds` |
| **SAML** | OOB IdP certs → signature bound to the assertion → NameID | one Assertion and one Signature per document; `AudienceRestriction` required when `lws.saml.audience` is set |
| **did:key** | Decode key from id → JWT | `aud` enforced; lifetime capped by `lws.token.max-lifetime-seconds` |

**Verdict:** Suite *shapes* are correct. Audience binding and self-signed token lifetimes are
enforced across the three JWT suites, and the SAML signature is now bound to the assertion whose
claims are used — the profile that buys it refuses a multi-assertion document, which rules out a
signed `samlp:Response` carrying unsigned assertions.

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

- Spec expects **authenticated** subscription create; anonymous creation is off by default (`lws.subscriptions.allow-anonymous`) and `lws.public-read` now defaults to **false**, so an anonymous subscriber no longer passes topic authorization by default either.
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

**Type sources:** the server's structural type, any `rdf:type` the resource's own representation asserts, **and client `Link: rel="type"` on a write** — the spec's preferred source, and the only one a binary resource has. A client may add types and never override: the whole `lws:` namespace and the LDP interaction models are refused, so it can describe its resource and cannot claim to be a container or a storage. A type search requires at least one `type` clause; without one it used to enumerate every resource the caller could read. Eventual-consistency of the index is acknowledged; in practice events are sync on the write path.

---

## Access requests & grants (core section) — yes

- Advertised services, create/list/delete style endpoints  
- Grants enforced via `GrantAuthorizer`  
- No `Control` via grant; fail-closed unknown constraints
- Issuance requires a configured storage controller (refused entirely while `lws.owners` is empty), `storage` and every `target.value` are validated against the storage root at creation, and a grant's authority is re-checked against its issuer at every evaluation — so removing an issuer from `lws.owners`, or revoking its `acl:Control`, deactivates its grants on the next request  
- Notifications to inboxes on create (when configured)  

Remaining issues are scale (load all grants) and notification SSRF on arbitrary inboxes — not “feature missing.”

---

## Scorecard

| Suite / area | Correct core model? | Completeness | Main residual issues |
|--------------|---------------------|--------------|----------------------|
| **LWS Core** | Yes | High for practical ops | Spec flux |
| **Vocab** | Yes | High | — |
| **Auth ×4** | Yes | High shape / high claim-strict | `azp` informational; single-assertion SAML profile |
| **Notifications** | Yes | High | Public-topic anonymous subscribe; webhook SSRF |
| **Search/Type Index** | Yes | High | Derivation source bias; unbounded in-memory type index at scale |
| **Access grants** | Yes | High | Perf under many grants; inbox SSRF |

---

## Bottom line

**Yes — `lws-server` correctly implements LWS Core and the other LWS suites in the sense that matters for a real storage:** resource/containment CRUD, storage description, linksets, the four auth credential shapes, webhook notifications with signed delivery and dual-time authz, type index/search with live authz filtering, and access requests/grants.

What it is **not**:

1. A **formal Rec-level conformance certificate** (core ED is incomplete; behavior fills gaps with LDP/Solid).  
2. **Bug-free** (concurrency/atomicity in particular; see `REVIEW.md` for what is fixed and what is not).  
3. **Claim-maximal** on every MUST in auth drafts (`aud`, etc.).

### Ship posture (protocol fidelity)

**Ship with fixes** — architecture and suite coverage are sound; production multi-tenant needs the security/concurrency fixes, not a rewrite of the protocol engine.

### Suggested next step

A checklist of MUST statements vs code for core Operations only (create/read/update/delete + linkset + storage description), line by line — that is where “conformance” will get sharper as the Editor’s Draft fills in.
