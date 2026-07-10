# Code Review: lws-server

**Date:** 2026-07-09
**Scope:** Full repository review of `lws-server`
**Reviewer:** automated full-repo review

## Executive Summary

LWS Server is a carefully structured W3C LWS Protocol implementation with a clean framework-free core (`LwsComponents`), solid transactional TDB2 usage for RDF metadata, and unusually thoughtful security plumbing for a protocol server of this size (outbound SSRF guard for auth/WAC fetches, SPARQL Update `LOAD`/`SERVICE` allow-list, DPoP, RFC 9421 webhook signatures, fail-closed access-grant constraints, conditional PUTs). The dominant residual risks are **server-side request forgery via webhook and access-notification delivery** (not covered by the fetch policy), **SAML assertion handling that may accept signature-wrapping payloads**, **HTTP redirect-follow SSRF residual** in document loaders, and **production-unsafe defaults** (`public-read=true`, empty owners = open mode, DPoP nonces off). Correctness risks include **If-Match checked outside the write transaction** (lost-update races) and **binary store writes not rolled back with RDF transactions**. Ship readiness for production multi-tenant use: **ship with fixes** after addressing webhook SSRF and SAML wrapping; single-tenant/owner mode with hardened config is closer.

## Architecture Overview

The design matches the README goals well: Spring Boot is limited to bootstrap (`LwsServer`, `LwsServletConfig`); protocol logic lives in plain Jakarta servlets and framework-free services. `RdfStore` cleanly abstracts TDB2 vs remote SPARQL; non-RDF bytes go through `BinaryStore`; authn suites (OpenID, SAML, SSI-CID, did:key) + DPoP feed a Shiro subject and an `Authorizer` (owner or WAC), optionally wrapped by `GrantAuthorizer`. Notifications, search index, access grants, linksets, and optional Fuseki sit as listeners/services on the same graph. The separation is maintainable and testable; the highest-risk surface is correctly concentrated in `auth/`, `ResourceService`, `AccessService`, and `notifications/`.

## Strengths

- Clear bootstrap seam (`LwsComponents` / dual Spring vs bare Jetty entry points) with no Spring leakage into protocol code.
- Configuration fail-fast validation with named keys and ranges (`LwsConfiguration`).
- Explicit open-mode warning at startup; README documents security-sensitive defaults.
- Outbound fetch SSRF policy for auth WebID/OIDC/WAC group loads: scheme allow-list, private/metadata/link-local blocking, fail-closed on DNS failure (`OutboundFetchPolicy`).
- SPARQL Update SSRF guard for `LOAD`/`SERVICE` with default-deny host list (`SparqlUpdateGuard`).
- Access grants: controller-only issue, never grant `Control`, fail-closed unknown constraints, hierarchical target matching is exact or trailing-slash prefix only (`AccessService`, `AccessServlet`).
- DPoP: rejects `alg:none`, checks `htm`/`htu`/`ath`/`jti`/`iat`, optional nonce, cnf.jkt binding (`DpopValidator`, `AuthenticationFilter`).
- Binary store path escape guard and atomic write-to-temp (`FileSystemBinaryStore`).
- Slug sanitization and binary-key `..` rejection (`Iris`).
- Container listing and search index filter members by live authorization (no authz caching).
- SAML XML parse hardened against XXE (`parseSecure` with secure-processing / no DTD / no external entities).
- Problem+json errors for HTTP failures; many unexpected exceptions map to generic 500 without stack traces to clients.
- Substantial test suite (auth suites, DPoP, WAC, grants, webhooks, quotas, reverse proxy, search authz, ops conformance, etc.).

## Issue Counts

- bugs: 8
- suggestions: 12
- nits: 4

## Issues

### Issue 1 -- Severity: bug
- File: `src/main/java/com/ebremer/lws/server/notifications/WebhookDispatcher.java:101-114`
- Description: Outbound webhook delivery posts to subscriber-supplied inbox URLs with no host/address policy. The same path is used for access-request/grant notifications (`deliverTo`, lines 51–61). An attacker who can create a subscription (any principal — including anonymous — that can `READ` a topic; default `public-read=true` makes that easy) or an authenticated access request with an `inbox` can force the server to HTTP POST to internal/metadata addresses (e.g. `http://169.254.169.254/…`, `http://10.x/…`). This is a classic webhook SSRF surface and is **not** covered by `OutboundFetchPolicy` / `lws.fetch.*`.
- Suggestion: Apply `OutboundFetchPolicy` (or a dedicated delivery policy) to every inbox URI before `sendSigned`; require `https` in production; block private/loopback/link-local/metadata; optionally allow-list hosts. Reject subscription/access-request create when the inbox fails the policy.
- Status: open

### Issue 2 -- Severity: bug
- File: `src/main/java/com/ebremer/lws/server/notifications/SubscriptionService.java:60-76`
- Description: Subscription creation does not require authentication. Combined with default public readability and Issue 1, an unauthenticated client can `POST` a `WebhookSubscription` for public topics and set an arbitrary private inbox, weaponizing the server as an internal scanner / metadata fetcher.
- Suggestion: Require a non-anonymous principal to create subscriptions (unless explicitly configured otherwise), and validate inbox URLs under the outbound policy at create time.
- Status: open

### Issue 3 -- Severity: bug
- File: `src/main/java/com/ebremer/lws/server/auth/SamlValidator.java:86-115` (and `signatureIsTrusted` at 122–139)
- Description: Validation accepts a document if **any** `ds:Signature` verifies under a trusted IdP key, then reads claims from the **first** `saml:Assertion` in document order (`firstElement`). It does not require that the Assertion used for `NameID`/Conditions is the same element covered by the validated signature. This is the classic SAML signature-wrapping shape: embed a valid signed assertion (or signed blob) for signature success while placing an attacker-controlled unsigned Assertion first for identity mapping.
- Suggestion: Locate the signed Assertion via the signature `Reference` URI / enveloped signature parent; only extract Issuer/Subject/Conditions from that element. Reject documents with multiple Assertions unless the validated one is explicitly selected. Add wrapping-focused unit tests.
- Status: open

### Issue 4 -- Severity: bug
- File: `src/main/java/com/ebremer/lws/server/auth/HttpDocumentLoader.java:29-32` and `src/main/java/com/ebremer/lws/server/auth/OutboundFetchPolicy.java:27-30`
- Description: `HttpDocumentLoader` uses `HttpClient.Redirect.NORMAL`, so redirects are followed after a single `permits(url)` check on the original URL. `LwsOpenIdValidator` / `WacAclService` use `RDFDataMgr.loadModel`, which also follows redirects without re-applying the policy. The residual risk is documented on the policy class, but it is still an active SSRF bypass: a public host that 30x-redirects to `http://169.254.169.254/` or an internal admin API is not fully prevented.
- Suggestion: Disable redirects, or re-validate every hop (scheme + resolved addresses) against the policy before following; consider pinning connections to the originally resolved safe address set.
- Status: open

### Issue 5 -- Severity: bug
- File: `src/main/java/com/ebremer/lws/server/http/LwsResourceServlet.java:360-365` and `472-480`; `src/main/java/com/ebremer/lws/server/core/ResourceService.java:209-250`
- Description: Conditional PUT evaluates `If-Match` in `requirePutPrecondition` via a separate `stat` read, then performs the write in a new TDB transaction in `ResourceService.put`. Two concurrent clients with the same fresh ETag can both pass the precondition and both commit, last-writer-wins, defeating optimistic concurrency. The same TOCTOU pattern applies to PATCH/DELETE (`checkIfMatch` at 459–464) and linkset preconditions (`enforceLinksetPrecondition` at 578–588).
- Suggestion: Re-check the ETag (or version) inside the write transaction and fail with 412 if stale; or use a compare-and-swap style update on the registry graph.
- Status: open

### Issue 6 -- Severity: bug
- File: `src/main/java/com/ebremer/lws/server/core/ResourceService.java:546-578` and `482-491`
- Description: Binary content is written/deleted via `BinaryStore` **inside** the RDF write callback, but filesystem operations are not part of the TDB2 ACID transaction (`Tdb2RdfStore.write` only wraps RDF). If the RDF transaction rolls back after a successful `blobs.write`, or the process crashes between blob replace and commit, you get orphan blobs and/or registry metadata that does not match bytes on disk. Conversely, a failed RDF commit after overwriting a blob key can leave destroyed previous content with old metadata after rollback.
- Suggestion: Write to a new content-addressed key (or temp key), commit RDF pointing at the new key, then garbage-collect old keys asynchronously; on failure delete the uncommitted key. Never overwrite the live key before commit.
- Status: open

### Issue 7 -- Severity: bug
- File: `src/main/java/com/ebremer/lws/server/auth/LwsOpenIdValidator.java:97-104`
- Description: ID token processing verifies signature, issuer, subject, and expiry, but does **not** verify `aud` (or an explicit LWS resource-server audience / `azp` allow-list). Any valid ID token from a subject-trusted issuer may be accepted as a bearer credential even if it was minted for a different relying party. That expands the blast radius of token leakage and cross-RP token replay.
- Suggestion: Require `aud` (or configured accepted audiences) to include this storage / configured client audience; optionally require `azp` when present. Document the LWS-suite expectation if the protocol deliberately omits `aud`.
- Status: open

### Issue 8 -- Severity: bug
- File: `src/main/java/com/ebremer/lws/server/http/HttpSupport.java:111-114`
- Description: Request bodies are fully buffered with `readAllBytes()` with no application-level size cap on the HTTP API path (UI forms cap at 64MB; API does not). A client can exhaust heap with a large PUT/POST/PATCH regardless of quota (quota only counts binary store totals after read).
- Suggestion: Enforce a configurable max request body (and/or stream to disk with a hard limit) before parsing; reject with 413.
- Status: open

### Issue 9 -- Severity: suggestion
- File: `src/main/java/com/ebremer/lws/server/LwsConfiguration.java:128-129`
- Description: Defaults `lws.public-read=true` and empty `lws.owners` (open mode). Documented and warned, but unsafe if an operator deploys without reading the security note. Open mode permits all reads/writes (`DefaultAccessPolicy`); WAC with no owners bootstraps public Control (`WacAclService.bootstrapRootAcl` ~293–302).
- Suggestion: Prefer fail-closed production profile defaults (`public-read=false`; refuse start without owners when a profile flag is set, similar to `lws.require-https`). Keep open mode only behind an explicit `lws.dev.open=true`.
- Status: open

### Issue 10 -- Severity: suggestion
- File: `src/main/java/com/ebremer/lws/server/LwsConfiguration.java:157` and `src/main/java/com/ebremer/lws/server/LwsComponents.java:122-123`
- Description: `lws.dpop.require-nonce` defaults to `false`. Without nonces, stolen DPoP proofs within the iat window that have not yet been seen as jti are still mitigated by jti cache, but RFC 9449 §8 nonce challenges are the recommended server-side hardening against precomputation / certain capture scenarios.
- Suggestion: Default nonces on for non-loopback deployments, or document strongly that production should set `lws.dpop.require-nonce=true`.
- Status: open

### Issue 11 -- Severity: suggestion
- File: `src/main/java/com/ebremer/lws/server/auth/LwsOpenIdValidator.java:124-127`
- Description: Subject document loads via `RDFDataMgr.loadModel(sub)` without the body-size bound used by `HttpDocumentLoader` (2 MiB). A hostile subject document can force large memory use during auth.
- Suggestion: Route OIDC subject (and ideally JWKS/discovery) through the same size-capped, policy-checked loader.
- Status: open

### Issue 12 -- Severity: suggestion
- File: `src/main/java/com/ebremer/lws/server/core/AccessService.java:191-226`
- Description: When any grant exists, every authorization check loads **all** grant JSON documents and evaluates them in memory. Under many grants / high QPS this is a DoS and latency risk (authorization on every container member filter multiplies cost).
- Suggestion: Index grants by assignee and/or target prefix; cache active grants with invalidation on create/delete; keep fail-closed semantics.
- Status: open

### Issue 13 -- Severity: suggestion
- File: `src/main/java/com/ebremer/lws/server/http/LwsResourceServlet.java:633-645`
- Description: ACL PUT requires `acl:Control` but does not require `If-Match` / optimistic concurrency. Concurrent Control holders can silently clobber ACL documents.
- Suggestion: Store an ETag for ACL graphs and enforce conditional PUT like resources/linksets.
- Status: open

### Issue 14 -- Severity: suggestion
- File: `src/main/java/com/ebremer/lws/server/http/LwsResourceServlet.java:378-387` and `450-456`
- Description: PATCH and DELETE only enforce `If-Match` when the header is present; unconditional PATCH/DELETE is allowed, while PUT replacement requires `If-Match` (428). Inconsistent optimistic concurrency for mutating methods.
- Suggestion: Align with lws10-core intent: require conditional headers for all replacing/deleting mutations on existing resources (with a clear exception list if any).
- Status: open

### Issue 15 -- Severity: suggestion
- File: `src/main/java/com/ebremer/lws/server/rdf/FusekiSparqlServer.java:15-47`
- Description: Optional embedded Fuseki endpoint intentionally bypasses WAC/owner auth and exposes admin graphs (registry, ACLs, grants, subscriptions). Defaults are safer (disabled; when enabled read-only + loopback), but misconfiguration (`loopback=false` and/or `read-only=false`) is catastrophic.
- Suggestion: When non-loopback or read-write is enabled, require an extra explicit acknowledge flag or refuse start; never advertise the endpoint in the storage description without auth.
- Status: open

### Issue 16 -- Severity: suggestion
- File: `src/main/java/com/ebremer/lws/server/ui/LwsWebApplication.java:72-73`
- Description: CSP is fully disabled for the Wicket UI so inline styles work. Combined with any future XSS in templates/labels, impact increases.
- Suggestion: Prefer a tight CSP with hashes/nonces for needed inline styles rather than `blocking().disabled()`.
- Status: open

### Issue 17 -- Severity: suggestion
- File: `src/main/java/com/ebremer/lws/server/ui/LoginPage.java:27-46` and `lws.properties:21-22`
- Description: Dev login impersonates any WebID when `lws.ui.dev-login=true`. The checked-in `lws.properties` enables it for local Keycloak setup. Dangerous if that file is reused outside a dev machine.
- Suggestion: Refuse `ui.dev-login` when `require-https` is true or base host is non-loopback; keep secrets/dev flags out of shared deployment configs.
- Status: open

### Issue 18 -- Severity: suggestion
- File: `src/main/java/com/ebremer/lws/server/notifications/WebhookKeys.java:44-49`
- Description: Webhook Ed25519 private seed is written with default filesystem permissions. On multi-user hosts the key file under `lws.data-dir/keys/` may be readable by other local users.
- Suggestion: Create the key file with owner-read-only permissions (POSIX `rw-------`) and document filesystem ACL expectations on Windows.
- Status: open

### Issue 19 -- Severity: suggestion
- File: `src/main/java/com/ebremer/lws/server/core/SearchIndexService.java:60-69`
- Description: Type index is an unbounded in-memory `ConcurrentHashMap` of every resource’s types. Documented trade-off, but large storages risk heap pressure and OOM.
- Suggestion: For large deployments, spill to TDB-backed secondary index or cap/rebuild strategy with clear operational guidance.
- Status: open

### Issue 20 -- Severity: suggestion
- File: `src/main/java/com/ebremer/lws/server/core/SparqlUpdateGuard.java:45-66`
- Description: Guard handles `UpdateLoad` and `SERVICE` inside `UpdateModify` WHERE patterns. Other remote-fetch shapes (if any engine-specific extensions) are not obviously covered; host checks use `URI.getHost()` only (no IP-literal private-range check beyond hostname allow-list — allow-listed hostnames that resolve to private IPs are permitted by design of this guard, unlike `OutboundFetchPolicy`).
- Suggestion: Resolve and block private addresses for LOAD/SERVICE unless explicitly allowed; walk all update operation types Jena can produce for remote access.
- Status: open

### Issue 21 -- Severity: nit
- File: `src/main/java/com/ebremer/lws/server/auth/AuthenticationFilter.java:123-134`
- Description: Unrecognized `Authorization` schemes are treated as anonymous rather than 401. Unusual schemes with credentials may silently fail closed to anonymous and then hit resource-level 401/403, which can be confusing for clients.
- Suggestion: Optionally 401 on present-but-unsupported schemes when a credential value is non-empty.
- Status: open

### Issue 22 -- Severity: nit
- File: `src/main/java/com/ebremer/lws/server/storage/FileSystemBinaryStore.java:66`
- Description: `Files.move(..., ATOMIC_MOVE)` can throw `AtomicMoveNotSupportedException` on some stores; the write then fails hard even when a non-atomic replace would succeed.
- Suggestion: Catch and fall back to non-atomic `REPLACE_EXISTING` with a warning.
- Status: open

### Issue 23 -- Severity: nit
- File: `src/main/java/com/ebremer/lws/server/auth/DpopValidator.java:94-128`
- Description: `jti` is recorded during `verifyProof` before the access token / cnf.jkt checks in `AuthenticationFilter`. A proof that verifies but fails later binding checks burns the jti (client must mint a new proof). Minor UX friction, not a security bypass.
- Suggestion: Record jti only after full authentication success, or document that clients must always use fresh jti per attempt.
- Status: open

### Issue 24 -- Severity: nit
- File: `src/main/java/com/ebremer/lws/server/LwsComponents.java:243-250`
- Description: `close()` shuts down the purge scheduler and webhook executor but does not await termination; in-flight deliveries may be cut mid-retry. Acceptable for process exit, slightly abrupt for hot reload/tests.
- Suggestion: `awaitTermination` with a short timeout after `shutdown`.
- Status: open

## Security Notes

**Posture overall:** Defense-in-depth is intentional and above average for an early protocol implementation. Authn validators reject `alg:none`, require expiry on SSI suites, and use allow-listed crypto. Authorization is fail-closed when no ACL/policy matches (WAC) or resource missing (owner mode). Access grants are carefully limited (no Control; unknown ODRL constraints deny). SPARQL Update remote fetch is default-deny. Fuseki is opt-in and loudly warned.

**Critical gaps:** Webhook/notification delivery is an unprotected outbound HTTP client driven by client-controlled URLs — the largest practical SSRF hole relative to the careful auth fetch policy. SAML validation appears incomplete against wrapping. Redirect following undermines the fetch SSRF guard. Production defaults (`public-read`, open mode, DPoP nonce off, optional dev-login) require operator diligence.

**Other notes:**
- `lws.behind-proxy=true` trusts `X-Forwarded-*` / `Forwarded`; correctly documented as only safe when a trusted proxy strips client headers.
- Open mode and WAC-without-owners are explicitly development fail-open modes — never deploy that way.
- Purpose (`LWS-Purpose`) and `Origin` for grants/WAC are client-asserted by design; not a crypto boundary.
- Checked-in `lws.properties` enables owners + Keycloak + `dev-login` + Fuseki for local work; treat as non-production sample only (contains a UI client secret).

## Test Coverage Assessment

**Strong coverage:** credential suite unit tests (did:key, SSI-CID, OpenID with mock OP, SAML, DPoP/nonce), WAC, outbound fetch policy, SPARQL update guard, JSON patch/merge, grants, access notifications, webhook delivery + RFC 9421, quotas, container pagination, reverse-proxy forwarding, search index authz, config validation, ACME wiring (non-network), UI smoke, ops conformance, end-to-end.

**Gaps / false confidence:**
- No tests that webhook or access-notification inboxes to private/metadata addresses are rejected (Issue 1–2) — current webhook tests intentionally use open mode and localhost inboxes.
- No SAML signature-wrapping adversarial cases (Issue 3).
- No concurrent If-Match race tests (Issue 5).
- No failure-injection tests for blob write vs TDB rollback (Issue 6).
- Outbound fetch tests do not cover redirect hops (Issue 4).
- OpenID audience rejection untested (Issue 7).
- Little coverage of large-body / 413 behavior (Issue 8).
- ACL conditional write, unconditional PATCH/DELETE policy, and Fuseki misconfiguration start refusals are lightly covered or absent.
- Integration tests often run open mode or owner-only setups; multi-tenant WAC + grants + webhooks together under hostile principals is thinner.

## Recommendations (prioritized)

1. **Block SSRF on all outbound delivery** (webhooks + access-notification inboxes): reuse/extend `OutboundFetchPolicy`, validate at subscription/request create, and add negative tests for private/metadata targets.
2. **Fix SAML assertion–signature binding** and add wrapping tests before enabling SAML in any production IdP integration.
3. **Stop following redirects (or re-check each hop)** for auth/WAC document loads; share one size-capped HTTP loader.
4. **Move If-Match / version checks into write transactions** for PUT/PATCH/DELETE/linkset (and ideally ACL).
5. **Make binary writes content-addressed / two-phase** so TDB rollback cannot desync blobs.
6. **Validate OIDC `aud`** (and document suite expectations).
7. **Cap request body size** on API writes.
8. **Harden production defaults** (or a `production` profile): no open mode, `public-read=false`, DPoP nonces on, refuse `dev-login` off-loopback, cautious Fuseki flags.
9. **Index or cache access grants** for authorization performance under load.
10. Extend the test suite toward adversarial multi-tenant scenarios (SSRF, wrapping, races) rather than only happy-path protocol conformance.

## Verdict

**Ship with fixes.**

The architecture and much of the security engineering are solid and suitable as a serious LWS Protocol implementation. It should not be exposed as a multi-tenant or internet-facing service until webhook/notification SSRF, SAML wrapping, redirect SSRF residual, and concurrency/blob atomicity issues are addressed, and production configuration defaults/profile are hardened. Single-tenant owner mode behind a trusted reverse proxy, with owners set, public-read false, DPoP nonces on, and webhooks restricted to trusted inbox hosts, is a more defensible interim deployment.
