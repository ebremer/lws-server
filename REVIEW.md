# Code Review: lws-server

**Date:** 2026-08-26
**Commit reviewed:** `33a3bb4` (working tree clean)
**Scope:** Full repository — 90 main sources (11,483 LOC), 34 test sources (4,264 LOC), build, configuration, docs
**Method:** 13 parallel subsystem reviewers → adversarial verification of every finding → three whole-system sweeps (completeness critic, threat model, architecture/conformance). 240 raw findings, 220 confirmed against the code; deduplicated to 138 distinct issues below.

---

## Executive summary

`lws-server` is a well-engineered W3C LWS Protocol implementation. The layering is genuinely good — a framework-free composition root (`LwsComponents`), a clean `RdfStore`/`BinaryStore` seam, `ParameterizedSparqlString` used consistently so there is **no SPARQL injection anywhere**, fail-closed authorization defaults in the ACL engine, `alg:none` rejected on every JWT path, a real RFC 9421 signature implementation, and RFC 9457/9530/7240/9264 support that most protocol prototypes never reach. The Javadoc is exceptional. `mvn test` is green: **141 tests, 0 failures, 31s**, clean compile with no deprecation warnings.

The defects are structural rather than sloppy, and they cluster in four recurring patterns:

1. **Namespace collisions between subsystems.** Resource content and WAC ACL documents are both addressed as TDB2 named graphs keyed by public IRI, with no reserved-name discipline between them. This yields a **critical, remotely exploitable privilege escalation**: `POST` with `Slug: .acl` lets an Append-only tenant author the ACL that governs the container — or the whole storage. The same pattern maps IRIs directly onto filesystem paths, colliding distinct resources onto one blob file on Windows/macOS.
2. **Signatures verified, claims unbound.** Every credential suite verifies cryptography correctly and then reads claims that the verified signature never covered. The SAML validator has a **working signature-wrapping (XSW) authentication bypass** — reproduced end-to-end against the project's own compiled classes. No suite checks `aud`. A DPoP-bound token is accepted verbatim under the `Bearer` scheme.
3. **The ACID boundary is drawn around TDB2 only.** Blob writes, ACL/linkset cleanup, and every `If-Match` precondition live outside the write transaction, so lost updates, orphaned ACLs, and byte/metadata divergence are all reachable.
4. **Outbound HTTP is guarded in one place and unguarded in three.** `OutboundFetchPolicy` is well built and correctly applied to auth fetches — but never to webhook/inbox delivery, never to JSON-LD `@context` resolution, and never re-applied after an HTTP redirect.

**Verdict: do not expose to an untrusted network until C1, C2 and the H1–H12 block are fixed.** A single-tenant, owner-mode deployment behind a trusted reverse proxy, with `lws.owners` set, `lws.public-read=false`, SAML disabled, notifications disabled, and Wicket forced to deployment mode, is defensible in the interim.

### Counts

| Severity | Count | Meaning |
|---|---|---|
| Critical | 2 | Remotely reachable authentication bypass / privilege escalation |
| High | 24 | Exploitable with modest preconditions, or silent data loss |
| Medium | 47 | Real bug with bounded blast radius, DoS, or protocol breakage |
| Low | 46 | Minor bug or hardening gap |
| Nit | 19 | Cosmetic but real |

Eleven candidate findings were **refuted** during verification and are not listed (e.g. "ThreadLocal leaks across pooled request threads" — the filter's `finally` hygiene is correct; "SPARQL injection" — `ParameterizedSparqlString.setIri` genuinely throws on injection attempts; "RDF/XML XXE" — Jena 5.6 routes RDF/XML through `RRX`/`JenaXMLInput` with external entities disabled).

---

## Method and confidence

Findings are marked **CONFIRMED** where a verifier read the cited code, the surrounding method, and its callers, and could not refute the claim. Several were verified by *executing* code against the project's own compiled classes and dependency tree:

- **C1 (SAML XSW)** — a proof of concept was built and run. Honest document → `LwsPrincipal[webId=https://alice.example/profile#me]`; the same genuine IdP-signed assertion re-parented into a `<saml:Advice>` under an unsigned wrapper → `LwsPrincipal[webId=https://attacker.example/profile#me]`.
- **C2 (`.acl` escalation)** — reproduced against `target/classes` with owners=alice, WAC, and a root ACL granting `acl:AuthenticatedAgent acl:Append`. Before: `bob CONTROL root = false`. After one `POST / Slug: .acl`: `bob CONTROL root = true`, **`alice CONTROL root = false`** — the owner is locked out with no HTTP recovery path.
- **H8 (SPARQL guard bypass)** — a harness confirmed `FILTER EXISTS { SERVICE <url> {...} }` passes `SparqlUpdateGuard.check` and that `UpdateAction.execute` really issues the outbound request (`GET /sparql?query=...` observed on a local listener). Top-level, sub-select, `OPTIONAL`, `MINUS`, `GRAPH` and `LOAD` forms are all correctly blocked; only the `EXISTS` family leaks.
- **H2 (OIDC `aud`)** — Nimbus' two-arg `DefaultJWTClaimsVerifier` was exercised directly: `getAcceptedAudienceValues()` returns `null` and `verify()` **passes** on a claims set with a foreign `aud`.
- **H5 / H4** — `javap -c org/apache/jena/http/HttpEnv` on the resolved jena-arq 5.6.0 shows `followRedirects(Redirect.ALWAYS)` and no read timeout or body cap, making the redirect bypass strictly broader than a `Redirect.NORMAL` client.
- **H14** — `Paths.get("C:/base").resolve("ABC").equals(Paths.get("C:/base").resolve("abc"))` returns `true` on this machine.
- **M27 (storage-description ETag)** — two `Etags.forModel` calls on an identically-built model produced `40ec162e5e06c3d7` and `d699cc4ca046b387`.

Findings marked **UNVERIFIED** come from the sweep stage and were not put through the adversarial pass; they are flagged inline.

---

## Architecture assessment

**What is well built.** `RdfStore` (44 lines) is a well-chosen seam: one `read`/`write` closure API over a Jena `RDFConnection`, so `Tdb2RdfStore` and `RemoteSparqlRdfStore` are interchangeable and the service layer never touches transactions. `ResourceRegistry` (226 lines) keeps all administrative metadata in one named graph and binds every IRI through `ParameterizedSparqlString`. `LwsComponents` (252 lines) is a real annotation-free composition root, and the README's headline claim holds exactly: `grep -rl org.springframework src/main/java` returns precisely `LwsServer.java` and `LwsServletConfig.java`. `Authorizer`/`AccessPolicy` separate the hierarchy-aware decision point from single-resource policy, and `GrantAuthorizer` decorating a base authorizer is an elegant way to layer ODRL grants over either owner or WAC mode. Configuration is a framework-free immutable POJO with typed, range-checked accessors whose errors name the key, the value and the expectation — and a full bidirectional cross-check of all 48 `lws.*` keys in `lws.example.properties` against `LwsConfiguration` came back **clean in both directions**, which is unusual and worth preserving.

**Where the structure fails.**

1. **`RdfStore` leaks its own atomicity guarantee.** It promises "the store wraps each read/write in the appropriate transaction", but `BinaryStore` writes/deletes happen *inside* the RDF callback (`ResourceService.java:570`, `:487`) with no transactional participation, and the `ResourceEventListener` fan-out that performs ACL and linkset *cleanup* runs **after** the commit and swallows exceptions (`ResourceService.java:621-631`). Deletion is therefore not atomic with respect to its own access-control state.
2. **`RequestContext` is a ThreadLocal side channel into authorization.** `Origin` and `LWS-Purpose` reach `WacAclService.originAllowed` and `AccessService.constraintSatisfied` without appearing in any signature. Because notification listeners run synchronously on the writer's thread, a *subscriber's* read authorization is partly decided from the *writer's* headers (M31).
3. **`LwsConfiguration` (735 lines, ~40 fields, ~70 accessors) is a god object** handed whole to every collaborator — `WebhookDispatcher` can see ACME domains; `SamlValidator` can see quota. There are no narrow config interfaces, which is also why nothing below `LwsComponents` is unit-testable without building the entire graph.
4. **Apache Shiro is wired but inert.** `ShiroSupport` installs a VM-global static `SecurityManager`, `AuthenticationFilter.java:77-87` builds and binds a `Subject` per request, and `LwsRealm.doGetAuthorizationInfo` mints roles and permissions that *nothing* consults — there is no `isPermitted`, `hasRole`, or `SecurityUtils.getSubject()` anywhere outside that file. The cost is a 30-minute session created per authenticated request (H20).
5. **Protocol rules live only in the servlet.** Conditional writes, reserved path suffixes, system-path routing and media-type checks are enforced in `LwsResourceServlet`; `ResourceService` and `LinksetService` — the same objects the Wicket console and the notification subsystem call directly — enforce none of them. Every "second entry point" finding (C2, M20, M42) descends from this.
6. **The dual bootstrap has drifted.** `LwsServletConfig` (175 lines) and `JettyLauncher.buildHandler` (`:186-239`) register the same six servlets and four filters twice and already differ: TLS/ACME and the HTTPS redirect exist only in the launcher (L58); the launcher's sessions never expire while Spring's time out at 30 minutes (M25); only the launcher catches `LwsConfigurationException` and exits cleanly, so the README's "fail fast with an actionable message" is false on the default Spring path; the launcher instantiates `SubscriptionServlet` twice (N10).

**Largest units:** `LwsConfiguration` 735, `LwsResourceServlet` 711, `ResourceService` 656, `AccessService` 540. **Longest methods:** `BrowsePage` constructor **157 lines** (`:55-212`), `LwsComponents` constructor 95, `LwsConfiguration` constructor 75. **Copy-paste:** `path(HttpServletRequest)` ×5, `sendProblem` ×4, `parsePage` ×2, and four divergent ETag comparators — one of which uses substring `contains`.

---

## Verified strengths

These were checked and held up; keep them.

- **No SPARQL injection.** Every query in the codebase goes through `ParameterizedSparqlString`. A verifier confirmed `setIri` throws `ARQException: SPARQL injection risk` on a hostile IRI.
- **No RDF/XML XXE.** Jena 5.6 routes `Lang.RDFXML` through `RRX` → `JenaXMLInput.createXMLReader()`, which disables `load-external-dtd` and both external-entity features. The SAML parser is independently hardened (`parseSecure`).
- **ThreadLocal hygiene is correct.** `RequestContext.clear()` is in an outer `finally` and `ThreadContext.unbindSubject()` in an inner one, so neither leaks across pooled request threads on any early-return or exception path.
- **Connection and transaction lifecycle is clean.** Every query uses `conn.queryAsk/queryConstruct/querySelect(query, rowAction)`, which close their own `QueryExecution`; models are explicitly copied out of read transactions before escaping; `patchSparql` works on a detached copy to avoid the store-backed-model aliasing trap.
- **WAC evaluation is fail-closed where it matters.** `resolve()` denies when no governing ACL is found; `acl:AuthenticatedAgent`/`acl:agent` require a non-null WebID; `acl:Control` correctly does **not** imply Read/Write; grants never confer Control; the parent walk terminates correctly at the root; `Iris.toPath` requires a `/` boundary so `/foo` cannot match `/foobar`.
- **ODRL constraint evaluation is fail-closed** on unknown operands and unknown operators.
- **DPoP covers the RFC 9449 happy-path checklist** correctly: `typ`, `alg != none`, public-key-only `jwk`, signature over the embedded key, `htm`/`htu` with query and fragment stripped, `iat` bounds, `jti` single-use, `ath`, and RFC 7638 thumbprint vs `cnf.jkt`. Pinning `htu` to `baseUri()` rather than the request `Host` is the right call behind a proxy. The nonce service uses `MessageDigest.isEqual`.
- **did:key multicodec constants are correct** (`0xed01`, `0x1200`→`0x80 0x24`, `0xe701`), and BouncyCastle's `decodePoint` validates EC points.
- **`SparqlUpdateGuard` is default-deny** — the allow-list defaults to empty, so `LOAD`/`SERVICE` are off unless explicitly enabled. (One traversal gap: H8.)
- **The RFC 9421 signature base is correct** apart from `@authority` normalization: component ordering matches the inner list, `@signature-params` is a proper structured-field inner list with parameters, no trailing newline, RFC 9530 `sha-256=:b64:` digest, `alg="ed25519"`, stable JWK-thumbprint `keyid` published at a JWKS endpoint.
- **Dual-time notification authorization** (create-time topic check plus delivery-time re-check) is the right design and is genuinely implemented.
- **The single-range parser is genuinely correct** — suffix, zero-length, inverted and overflow cases all land on sane 416-or-ignore outcomes.
- **Search index authorization is evaluated live per request**, never cached alongside the derived index.
- **Config keys are in perfect sync with the documented example** (48/48, both directions), and `toString()` deliberately omits `lws.oidc.client-secret`.
- **Repo hygiene is clean.** `git ls-files` shows no committed secrets or state; the live `lws-data/` TDB2 store, the Ed25519 webhook key, `server.log`, `lws.properties` and `target/` are all correctly ignored — a naive `git add -A` would sweep in nothing.

---

# Critical findings

## C1 — SAML signature wrapping: the validated signature is never bound to the Assertion whose claims are used — **FIXED**

**`auth/SamlValidator.java:86-95`, `:122-140`, `:237-245`** · security · CONFIRMED (PoC executed)

`validate` selects the claims-bearing element positionally — `Element assertion = firstElement(doc, SAML_NS, "Assertion")`, where `firstElement` is `doc.getElementsByTagNameNS(ns, local).item(0)` (`:237-240`) — and then, completely independently, calls `signatureIsTrusted(doc)` (`:92`). That method walks **every** `ds:Signature` in the whole document and returns `true` as soon as any one validates under any trusted key (`:123-132`). Nothing compares the validated `Reference` URI to the assertion's `ID`. `registerIdAttributes` (`:223-235`) actively enables the attack by marking `ID` on *every* Assertion, so a wrapped-away original's `Reference URI="#_a1"` still resolves and still digests correctly. Compounding it, `firstChild` (`:242-245`) is a *descendant* search (`getElementsByTagNameNS`), not a child scan, so the outer wrapper's own `Issuer`/`NameID`/`Conditions` win by document order.

**Impact.** Any holder of any assertion signed by a configured IdP key authenticates as **any WebID they choose** — including the storage owner. Reachable over HTTP: `AuthenticationFilter.java:126-133` routes `SAML2` (and `Bearer`, via `LwsCredentialValidator.java:55` falling through for non-JWT credentials) straight into `saml.validate(...)`. Gated only on `config.samlEnabled()`.

**Reproduced.** Honest document → `Optional[LwsPrincipal[webId=https://alice.example/profile#me, issuer=https://idp.example]]`. The same genuine signed assertion re-parented into a `<saml:Advice>` under a new unsigned root Assertion carrying `NameID=https://attacker.example/profile#me` → `Optional[LwsPrincipal[webId=https://attacker.example/profile#me, issuer=https://idp.example]]`.

The existing `rejectsTamperedAssertion` test (`SamlValidatorTest.java:87-93`) does not catch this because it edits the signed element in place rather than wrapping it.

**Fix.** Stop scanning the document for signatures. Resolve the `ds:Signature` that is a *direct child* of the assertion you intend to use, validate it, then assert that the validated `Reference` URI is `#<that assertion's ID>` and that `assertion.isSameNode(context.getElementById(refId))`. Reject documents containing more than one `Assertion` or more than one `Signature`; reject an empty `Reference` URI and any non-enveloped transform chain. Replace `firstChild` with a real direct-child scan that skips `<saml:Advice>` subtrees. Set `context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE)` explicitly. Add the wrapped payload above as a regression test.

**Interim mitigation:** set `lws.saml.idp-certificates` empty (disables the suite).

---

## C2 — WAC privilege escalation: `POST` with `Slug: .acl` overwrites the governing ACL graph (Append ⇒ Control) — **FIXED**

**`core/Iris.java:101-124`, `core/ResourceService.java:192-194` + `:557`, `auth/WacAclService.java:204-210`** · security · CONFIRMED (PoC executed)

WAC stores every ACL as a named graph whose name is an ordinary resource IRI: `aclIriFor(target)` returns `config.baseUri() + path + ".acl"` (`WacAclService.java:204-210`), and `resolve`/`fetchAcl` read exactly that graph (`:112`, `:237-239`). Resource *content* is stored in a graph named by the resource's own IRI: `storeContent` does `conn.put(iri, m)` (`ResourceService.java:557`). Nothing keeps the two namespaces apart:

1. `Iris.sanitizeSlug` (`Iris.java:101-124`) permits `.` (`:112-113`) and only blanks segments that are *entirely* dots (`:121`, `replaceAll("^\\.+$", "")`). `.acl`, `.meta`, `secret.acl` all survive verbatim.
2. `ResourceService.create` authorizes only `AclMode.APPEND` on the **container** (`:190`), then builds `childPath = containerPath + name` (`:193`) and `childIri = pathToIri(childPath)` (`:194`) — byte-identical to `aclIriFor(container)`.
3. `chooseName` (`:597-610`) de-duplicates only against `registry.exists`, and ACL graphs are never registry subjects, so there is never a collision — the POST **silently replaces** any existing legitimate ACL.
4. The servlet's `.acl` guard (`LwsResourceServlet.java:64-67` → `handleAcl`, which correctly demands `acl:Control`) inspects only the **request** path. A `POST` targets the container, so the guard never fires.

**Impact.** In WAC mode, an agent holding only `acl:Append` on any container — a drop-box, an inbox, any shared space; and with `acl:AuthenticatedAgent` that is effectively anyone, since `DidKeyValidator` accepts self-minted credentials with no registration — sends:

```http
POST /c/ HTTP/1.1
Slug: .acl
Content-Type: text/turtle

<#pwn> a acl:Authorization ;
  acl:accessTo </c/> ; acl:default </c/> ;
  acl:agent <did:key:zMallory> ;
  acl:mode acl:Read, acl:Write, acl:Control .
```

and takes Read/Write/Control over the container and — via `acl:default` — its whole subtree. Variants: `Slug: secret.acl` seizes a *sibling* resource they had no access to at all (an own-ACL outranks inheritance); the ACL can be planted **before** the target exists, so a later-created resource is born under the attacker's ACL; and `POST /` with `Slug: .acl` replaces the bootstrapped **root** ACL for total storage takeover.

**Reproduced.** With owners=alice, WAC, root ACL granting `acl:AuthenticatedAgent acl:Append`: before, `bob WRITE root=false, CONTROL root=false`; after one POST, `bob READ/WRITE/CONTROL root=true`, `bob WRITE /alice-private/secret=true`, and **`alice CONTROL root=false`** — the owner is locked out, and `handleAcl` refuses to `DELETE` the root ACL (`LwsResourceServlet.java:646-648`), so there is no HTTP recovery path.

**Fix (two layers, do both).**
1. *Reserve the namespace in the write path, not just the router.* Reject any created/PUT path whose final segment ends in `.acl` or `Iris.LINKSET_SUFFIX` (`.meta`), or that matches `config.isSystemPath(...)`, inside `ResourceService.chooseName`/`create`/`put` — before `storeContent` runs. Keep the reserved-suffix list in one shared place so routing and creation cannot drift.
2. *Stop using a client-reachable IRI as the ACL graph name.* Store ACLs under an internal graph namespace — `urn:x-lws:acl:<targetIri>`, matching the `urn:x-lws:admin` / `urn:x-lws:linkset` / `urn:x-lws:access` pattern already used elsewhere — and keep `<resource>.acl` purely as the externally advertised address.

Add a startup scan/migration: a store built in OWNER mode (where `aclService` is null and `*.acl` names are unreserved) can **already contain** such graphs, which become live ACLs the moment the operator switches to `wac`.

**Interim mitigation:** stay in OWNER mode, or deny `POST` to containers for non-controllers.

---

# High findings

> **H1–H15 were fixed on 2026-08-26.** Each entry below is kept as the record of what was wrong;
> see "Fixed: H1–H15" at the end of this document for what changed. Everything else remains open.

## H1 — A DPoP-bound access token is accepted as a plain `Bearer` token — **FIXED**
**`auth/AuthenticationFilter.java:126-133`** · security · CONFIRMED

The `Bearer`/`SAML2` branch calls `validator.validate(value)` and returns the principal with **no inspection of the token**. The only `cnf` check in the entire codebase is `DpopValidator.isBoundTo` (`:141-149`), reachable only from `authenticateDpop` when the scheme is literally `DPoP`. RFC 9449 §7.1 requires the opposite. `lws.dpop.require-nonce` does not help — it only affects requests that already chose the DPoP scheme.

**Impact.** A sender-constrained token that leaks (proxy access log, APM trace, browser devtools, XSS) is replayed with `Authorization: Bearer <token>` and no proof. The entire proof-of-possession mechanism is bypassed by changing one word. The README's claim that "a stolen token is useless without the holder's private key" is false.

**Fix.** In the Bearer branch, after validation, parse `cnf` and reject with 401 `invalid_token` when `cnf.jkt` is present. Add a `DpopValidator.isSenderConstrained(token)` helper beside `isBoundTo`. Add an `lws.dpop.require` setting that refuses `Bearer` outright, and correct the README.

## H2 — OIDC ID token `aud`/`azp` are never validated — **FIXED**
**`auth/LwsOpenIdValidator.java:99-101`** · security · CONFIRMED (executed)

`new DefaultJWTClaimsVerifier<>(new JWTClaimsSet.Builder().issuer(iss).build(), Set.of("sub", "exp"))` — the two-arg Nimbus overload takes only exact-match and required claims; there is no accepted-audience argument, so `aud` is neither required nor checked. `azp` is read at `:89` and only copied into `LwsPrincipal` at `:104` — never compared. The `iss` exact-match is tautological: `iss` is read out of the token itself at `:83` and fed back as the expected value at `:100`. There is no `lws.oidc.audience` key, so an operator cannot even opt in.

**Verified:** with that exact construction, `getAcceptedAudienceValues()` returns `null` and `verify()` **passes** on `aud=https://attacker-registered-client.example`.

**Impact.** Any relying party of the same OP — including one the attacker registers — receives the victim's ID token and can replay it here as the victim. The same gap admits other same-issuer token types carrying `iss`/`sub`/`exp` (e.g. back-channel logout tokens).

**Fix.** Add a configured accepted-audience set (default: `config.baseUri()` and/or `lws.oidc.client-id`) and use `new DefaultJWTClaimsVerifier<>(Set.of(audience), exactMatch, Set.of("sub","exp","aud"))`. Validate `azp` against an allow-list when present. COMPLIANCE.md:78 already records this as a known deviation — close it rather than documenting it.

## H3 — did:key and SSI-CID tokens have no audience check and no lifetime cap — **FIXED**
**`auth/JwsSupport.java:40-43`** · security · CONFIRMED (executed)

`notExpired` is the entire temporal check: `exp != null && exp.getTime() > now - CLOCK_SKEW_MS`. There is no upper bound on `exp`, no `nbf`, no `iat`, and neither `SsiCidValidator` (`:44-86`) nor `DidKeyValidator` (`:31-51`) touches `aud`. These are bearer credentials the client mints itself.

**Verified:** a JWT with `sub`=`iss`=`client_id`, `aud=https://some-other-server.example`, and `exp = now + 100 years` was accepted.

**Impact.** A token minted for storage A authenticates at storage B — so a malicious or compromised LWS storage can replay its users' credentials against every other storage they use, indefinitely and unrevocably. (Note `DidKeyTool.java:50,68-70` already *mints* an `aud`; nothing verifies it.)

**Fix.** Require `aud` to contain this server's identifier; reject `exp - iat` beyond a configured maximum (10 minutes is generous for a self-signed PoP token); reject future `nbf`/`iat` beyond `CLOCK_SKEW_MS`; add a `jti` replay cache like `DpopValidator.recordJti`.

## H4 — Unbounded, pre-signature-verification fetch of the token's `sub` — **FIXED**
**`auth/LwsOpenIdValidator.java:126`** · reliability/security · CONFIRMED

`isTrusted` dereferences the token's `sub` with bare `RDFDataMgr.loadModel(sub)` after only a `fetchPolicy.permits(sub)` check. Jena 5.6.0's default client (verified by disassembling `HttpEnv`) sets a 10s connect timeout and `Redirect.ALWAYS`, and **no read timeout and no body size limit** — unlike `HttpDocumentLoader`, which enforces 2 MiB / 10s / 15s. Critically, `isTrusted` is called at `:91`, **eleven lines before** `proc.process(jwt, null)` at `:102` — so the fetch happens on a token whose signature has not been checked at all. Only `SignedJWT.parse`, an `alg != none` test, and presence of `iss`/`sub` precede it. The trust cache stores only successes (`:148-150`), so a hostile subject re-fetches on every request.

**Impact.** Unauthenticated. (a) A slowloris subject parks a Jetty thread forever — ~200 requests take the server down. (b) A multi-gigabyte Turtle document is buffered into a heap-resident `Model`, and the resulting `OutOfMemoryError` is an `Error`, so it escapes the `catch (RuntimeException)` at `:127` and the `catch (Exception)` at `:105`. (c) A 302 to `http://169.254.169.254/` is followed with no second policy check.

**Fix.** Route this fetch (and discovery/JWKS) through the same size-capped, timeout-bounded, policy-checked loader; parse from the bounded byte array. Defer `isTrusted` until after signature verification. Cache negative results.

## H5 — The SSRF guard is not re-applied to redirect targets in either outbound loader — **FIXED**
**`auth/HttpDocumentLoader.java:29-32` + `:40`; `auth/WacAclService.java:189` + `:194`** · security · CONFIRMED

`HttpDocumentLoader` builds its client with `.followRedirects(HttpClient.Redirect.NORMAL)` and calls `fetchPolicy.permits(url)` exactly once, on the attacker-supplied URL. The JDK client then follows 30x hops itself with no policy callback. The Jena paths are worse: `HttpEnv` uses `Redirect.ALWAYS`, which also follows HTTPS→HTTP downgrades. `OutboundFetchPolicy.java:27-30` calls this a "residual risk"; it is a complete bypass of the control.

**Impact.** `attacker.example` passes `permits()` (public address), then answers `302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/`. For the WAC group path the fetched document is parsed as RDF and its `vcard:hasMember` triples are consulted, giving a semi-blind oracle; varying the `Location` turns the server into an internal port scanner.

**Fix.** Use `Redirect.NEVER` and follow hops manually, re-running `permits` on each (with a hop cap). Replace `RDFDataMgr.loadModel` on untrusted URLs with a bounded fetch + `RDFParser` over the bytes. Register a Jena `RegistryHttpClient` entry so `RDFDataMgr` uses the hardened client. Best: share **one** hardened loader between `HttpDocumentLoader`, `LwsOpenIdValidator` and `WacAclService` so the guard cannot drift.

## H6 — Webhook and inbox delivery never consults `OutboundFetchPolicy` (unauthenticated blind SSRF) — **FIXED**
**`notifications/WebhookDispatcher.java:51-115`; `core/AccessService.java:167`; `notifications/SubscriptionService.java:68`** · security · CONFIRMED

`sendSigned` does `HttpRequest.newBuilder(inbox).POST(...)` on a URI that came verbatim from client JSON. `WebhookDispatcher`'s constructor takes no policy and its import list contains none; `LwsComponents.java:118-121` hands the policy only to the auth loaders. `SubscriptionService.create` checks only that `inbox` is a JSON string (`:225-228`); `AccessService.notificationInboxes` pulls `string(doc, "inbox")` straight out of a client-posted access request.

**Impact.** Two triggers. (a) **Anonymous** — with the shipped defaults (`lws.owners` empty ⇒ open mode; `lws.public-read=true`), `POST /.lws/subscriptions` with `topic: ["http://host/"]` and `inbox: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"`, then touch any resource. (b) **Immediate, needs only a self-minted did:key** — `POST /.lws/access-requests` with a hostile `inbox` fires the POST as soon as the request is accepted. The blind SSRF becomes a **read oracle**: `recordDelivery` persists `lws:failureCount`/`lws:active`, and `SubscriptionServlet.getOne` serves them back — 0 means that host:port answered 2xx. A working internal host/port scanner with answers returned over HTTP.

**Fix.** Thread an `OutboundFetchPolicy` (or a dedicated delivery policy with its own allow-list) into `WebhookDispatcher` and reject any inbox failing `permits()` before `sendSigned`; validate at *creation* in `SubscriptionService.create` and `AccessService.normalize` so a bad inbox is a 400; require `https` for non-loopback inboxes; and stop exposing per-delivery outcome, or coarsen it.

## H7 — Anonymous, uncapped, never-expiring, unmanageable subscriptions — **FIXED**
**`http/SubscriptionServlet.java:52`; `notifications/SubscriptionService.java:60-91`** · security · CONFIRMED

`SubscriptionServlet.service` passes `AuthenticationFilter.principal(req)` to `create` with no anonymity check — contrast `AccessServlet.create`, which explicitly rejects `LwsPrincipal.isAnonymous`. The only gate is the per-topic `resources.canRead`, which is open under the shipped defaults. There is no per-subscriber cap, no per-IP cap, and no default or maximum `expires`. Worse, `requireManage` (`:140-153`) matches `webId.equals(sub.subscriberWebId())`, and an anonymously-created subscription has `subscriberWebId == null` — so it can **never** be matched: the anonymous creator gets 401 and every authenticated non-owner gets 403. Only a configured storage owner can clean them up. `SubscriptionServlet` also authorizes against `config.isOpenMode()`/`config.ownerWebIds()` rather than the configured `Authorizer`, so in WAC mode it **fails open** relative to the rest of the server (M43).

**Impact.** Unbounded permanent records in `urn:x-lws:subscriptions`; because `NotificationEmitter` re-reads that whole graph on every write (M32), every mutation in the server slows proportionally, and each fans out a delivery to the attacker's inbox.

**Fix.** Reject anonymous creation unless an explicit `lws.subscriptions.allow-anonymous` flag is set; enforce a per-subscriber cap and a default/maximum `expires`; handle `subscriberWebId == null` in `requireManage`; and replace the config-based authority test with `resources.canControl(principal, config.storageRootIri())`.

## H8 — `SERVICE` inside `FILTER EXISTS`/`NOT EXISTS` bypasses the SPARQL Update SSRF guard — **FIXED**
**`core/SparqlUpdateGuard.java:49-63`** · security · CONFIRMED (executed)

`check()` walks only `modify.getWherePattern()` with `ElementWalker.walk(..., ElementVisitorBase{ visit(ElementService), visit(ElementSubQuery) })`. Jena's default `EltWalker.visit(ElementFilter)` is only `before/proc.visit/after` — it never descends into the filter's `Expr`, so an `ElementService` inside an `E_Exists`/`E_NotExists` is never visited.

**Verified** against the project's own classpath with the default **empty** allow-list:

```
blocked      top-level SERVICE
blocked      subselect SERVICE
blocked      OPTIONAL SERVICE
blocked      MINUS SERVICE
NOT BLOCKED  FILTER EXISTS SERVICE
NOT BLOCKED  FILTER NOT EXISTS SERVICE
NOT BLOCKED  FILTER EXISTS subselect SERVICE
```

and passing the surviving update through `UpdateAction.execute` (exactly what `ResourceService.patchSparql:284` does) produced an observed outbound `GET /sparql?query=...` on a local listener.

**Impact.** `PATCH /doc` with `Content-Type: application/sparql-update` and `... WHERE { ?s ?p ?o FILTER EXISTS { SERVICE <http://169.254.169.254/latest/meta-data/> { ?a ?b ?c } } }` reaches the metadata endpoint with an attacker-chosen path and query. The boolean `EXISTS` result and response latency form the oracle. Requires WRITE — which in the default open mode is anyone.

**Fix.** Use the three-arg `ElementWalker.walk(element, elementVisitor, exprVisitor)` with an `ExprVisitor` that recurses into `E_Exists`/`E_NotExists` bodies — or, provably complete, walk `Algebra.compile(...)` with an `OpVisitor` that rejects every `OpService`, since the algebra flattens `EXISTS`. Add regression tests for both `EXISTS` shapes.

*(The prior review's other two speculations here do not hold: `UpdateDeleteInsert extends UpdateModify`, so `instanceof UpdateModify` covers it, and `UpdateData`/`UpdateDeleteWhere` hold quad accumulators with no `Element` and thus no possible `SERVICE`.)*

## H9 — JSON-LD `@context` is dereferenced by Titanium's default loader (SSRF + `file://` read) — **FIXED**
**`rdf/RdfIO.java:27`** · security · CONFIRMED

`RdfIO.parse` calls the four-arg `RDFDataMgr.read(m, stream, baseIri, lang)` with **no RIOT `Context`**. For `Lang.JSONLD`, Jena 5.6 uses `LangJSONLD11`, whose `getJsonLdOptions` falls back to a bare `new JsonLdOptions()` when the `riot/jsonld#options` symbol is absent — and that delegates to `SchemeRouter.defaultInstance()`, wiring `http`/`https` to `HttpLoader` and `file` to `FileLoader`. Nothing in the repo ever sets that symbol.

**Impact.** Every remote `@context`/`@import` IRI in a client-supplied JSON-LD body is fetched by the server, completely bypassing `OutboundFetchPolicy` — the control built for exactly this. Reachable from `storeContent` (any PUT/POST with `application/ld+json`), `patchMerge` (`:326`), ACL PUT (`LwsResourceServlet.java:638`), and the Wicket UI (`BrowsePage.java:300`). In the shipped default configuration this is reachable **anonymously**:

```
curl -X PUT http://host/x -H 'Content-Type: application/ld+json' \
  -d '{"@context":"http://169.254.169.254/latest/meta-data/","a":1}'
```

`"@context":"file:///etc/passwd"` gives a file-existence oracle, and any on-disk JSON that parses as a context injects terms into the stored graph.

**Fix.** Install one hardened `com.apicatalog.jsonld.loader.DocumentLoader` that refuses every scheme but https, runs each URL through `OutboundFetchPolicy.permits`, caps body size, sets a timeout, and does not blindly follow redirects — via `RIOT.getContext().set(LangJSONLD11.JSONLD_OPTIONS, opts)` at startup or a per-parse `Context`. Remote contexts are not needed to store user data; a loader that always throws (inline `@context` only) is the safest default.

## H10 — Stored XSS: uploaded content is served with the client's `Content-Type` and no `nosniff`/CSP — **FIXED**
**`http/LwsResourceServlet.java:286`** · security · CONFIRMED

`writeBinary` does `resp.setContentType(meta.contentType() == null ? "application/octet-stream" : meta.contentType())`, and `meta.contentType()` is verbatim client input (`ResourceService.java:574-575` only strips parameters and lowercases). A repo-wide grep for `nosniff`, `Content-Security-Policy`, `X-Frame-Options`, `Content-Disposition` returns **zero hits**, and the Wicket console at `/app/*` on the same origin explicitly disables CSP (`LwsWebApplication.java:73`). `BrowsePage.java:224` likewise stores `fu.getContentType()` from the multipart part verbatim, and `:167` renders a direct link to the bytes.

**Impact.** Anyone who can write a resource can publish active content (`text/html`, `image/svg+xml`, `application/xhtml+xml`) that executes in the storage's own origin — the origin that serves the session-cookie-authenticated console. With the shipped defaults this is reachable unauthenticated. Combined with H11 (no CSRF defence), the script can drive `/app/browse` as any signed-in console user, read the pre-filled ACL editor, and POST a rewritten ACL granting itself `acl:Control`.

**Fix.** Always emit `X-Content-Type-Options: nosniff` on data-resource responses. For non-RDF resources, coerce an active-content allowlist (`text/html`, `application/xhtml+xml`, `image/svg+xml`, `application/xml`) to `application/octet-stream` with `Content-Disposition: attachment`, or add `Content-Security-Policy: sandbox; default-src 'none'`. Serving user content from a separate origin is the stronger fix. Also allow-list the stored media type rather than trusting `fu.getContentType()`.

## H11 — No CSRF protection at all in the Wicket console, and every destructive action is a GET link — **FIXED**
**`ui/LwsWebApplication.java:70-77`** · security · CONFIRMED

`init()` mounts three pages and disables CSP but never adds `ResourceIsolationRequestCycleListener` — verified **not** installed by default in wicket-core 10.8.0 (`WebApplication.internalInit()` contains zero references to it; no class in the jar mentions it but the listener itself). Wicket has no CSRF token, and a stateful callback URL is `?<pageId>-<n>.<componentPath>` with a small per-session sequential page id, so the URLs are guessable. Every destructive operation is a `Link`, i.e. an `<a href>` GET: `del` (`BrowsePage.java:102-109`), `deleteRdf` (`:151-158`), `deleteBin` (`:180-187`), `deleteAcl` (`:204-210`), `signout` (`BasePage.java:32-39`). Nothing sets `SameSite`/`Secure`/`HttpOnly` on the session cookie.

**Impact.** `<a target=_blank href="https://storage.example/app/browse?0-1.-rdfBox-deleteRdf">` on a hostile page is a top-level GET navigation, so the cookie is sent even under Chrome's Lax-by-default, and the resource the user last viewed is deleted. Because they are `<a href>` GETs, the same URLs are followed by link prefetchers, chat/email link scanners and "save page" crawlers.

**Fix.** Add `getRequestCycleListeners().add(new ResourceIsolationRequestCycleListener())`; convert the five destructive links to POSTing controls; set `SameSite=Strict`, `Secure`, `HttpOnly` on the session cookie.

## H12 — Request bodies are fully buffered into an unbounded `byte[]` **before** any authorization check — **FIXED**
**`http/HttpSupport.java:111-115`** · reliability · CONFIRMED

`readBody` is `try (var in = request.getInputStream()) { return in.readAllBytes(); }` — no cap, no `Content-Length` pre-check — and no container limit exists either (`JettyLauncher.java:163-167` builds a bare `HttpConfiguration`; grep for `setMaxFormContentSize|maxRequestSize` over `src/main` returns nothing). The **ordering** is what makes it pre-auth: `handlePost` reads at `:350` and only then calls `service.create` at `:352`, where `authorize(...)` finally runs (`ResourceService.java:190`); same for PUT (`:363-365`) and PATCH (`:381`). `SubscriptionServlet.create` (`:96`) and `SearchIndexServlet.parsePostFilter` (`:163`) stream straight into `Json.createReader` with no authorization in front at all. `enforceQuota` runs on `bytes.length` *after* the array exists. The only limits anywhere are the 64 MB `setMaxSize` on the two Wicket forms.

**Impact.** With the storage fully locked down (owners set, public-read false, restrictive WAC), an attacker **with no credential** opens 8 connections and streams 1 GB of chunked JSON to `POST /.lws/type-search`; the JVM OOMs before a single authorization decision is made. A body over 2 GiB makes `readAllBytes` throw `OutOfMemoryError`, which escapes the `catch (RuntimeException)` in `LwsResourceServlet.service`.

**Fix.** Add `lws.max-request-bytes`; reject early on `Content-Length` and wrap chunked bodies in a counting stream that throws 413. Apply it in `HttpSupport.readBody` and at every raw `getInputStream()` call site (`SubscriptionServlet:96`, `SearchIndexServlet:163`, `AccessServlet:124`). Move the authorization decision ahead of body consumption for POST/PUT/PATCH. Set `HttpConfiguration` limits in both launchers as defence in depth.

## H13 — Binary blob writes/deletes run inside the RDF transaction but survive its rollback — **FIXED**
**`core/ResourceService.java:570`, `:487`** (also `:348`, `:394`) · correctness · CONFIRMED

`storeContent` calls `blobs.write(key, ...)` and `deleteContent` calls `blobs.delete(...)` from inside the `rdf.write` lambda, but `Tdb2RdfStore.write` wraps only the RDF work; the filesystem side effect is irreversible. Because keys are deterministic (`Iris.binaryKey(path)`), `FileSystemBinaryStore.write` does `Files.move(tmp, target, REPLACE_EXISTING, ATOMIC_MOVE)` onto the **live** key — destroying previous content *before* the metadata describing it is committed.

**Impact.** A 4 MB `/photo.jpg` is replaced by a 12-byte PUT; the write transaction then aborts (full disk, journal I/O error, or a later `registry.put` failure). Metadata still says 4 MB, so `GET` sets `Content-Length: 4194304` and streams 12 bytes, and `Repr-Digest` advertises the SHA-256 of content that no longer exists. In recursive DELETE (`:440-444`) every descendant's blob is unlinked before the commit; a commit failure leaves all bytes gone and all registry entries alive, so every subsequent GET 500s on `NoSuchFileException`. A realistic trigger on Windows: resource #300's blob is locked by a virus scanner, `deleteContent` throws, and the 299 already-unlinked blobs are unrecoverable.

**Fix.** Make the blob store commit-ordered: write to a fresh content-addressed or staging key, commit the RDF pointing at the new key, then unlink the superseded key from an async sweeper; delete the staged key on abort. Never `Files.move` onto the live key and never `blobs.delete` before commit. `BinaryStore` needs a `writeStaged(key) → commit(key)/discard(key)` operation for this to be expressible at all.

## H14 — Blob keys are raw, un-escaped, case-preserved request paths — **FIXED**
**`core/Iris.java:131-139`; `storage/FileSystemBinaryStore.java:35-41`** · security/correctness · CONFIRMED

`Iris.binaryKey` strips the leading `/`, rejects a literal `..` segment, and otherwise returns the path **verbatim** — and `path` is `req.getRequestURI()`, i.e. raw, still-percent-encoded and case-preserved. `FileSystemBinaryStore.resolve` maps it straight onto the filesystem with only a `startsWith(base)` traversal check. IRIs are compared case-sensitively everywhere in the RDF layer, so `/c/Secret` and `/c/secret` are two resources with independent owners, ACLs, sizes and digests — but **the same file** on NTFS and default APFS/HFS+ (verified: `Paths.get("C:/base").resolve("ABC").equals(...resolve("abc"))` → `true`).

**Impact.** Bob, holding only Append on `/c/`, PUTs a 1-byte `/c/secret`. Alice PUTs 10 KB to `/c/Secret`; the same NTFS file is replaced. Bob GETs his own `/c/secret` — authorization passes on *his* resource — and reads Alice's plaintext. Reversed, Bob's 1-byte PUT destroys Alice's content while her metadata still advertises 10 KB and the old digest. The same collapse hits trailing dots/spaces (`/note.` vs `/note`) and percent-encoding case (`/caf%c3%a9` vs `/caf%C3%A9`, normalization-equivalent per RFC 3986 §6.2.2.1). Separately, `/a` (a file) and `/a/b` (needing `/a` to be a directory) are mutually exclusive: `Files.createDirectories` throws `FileAlreadyExistsException` → a permanent 500 instead of a 409 (M24).

**Fix.** Stop deriving blob keys from the IRI. Generate an opaque key at creation (UUID or content SHA-256, sharded two levels) and persist it in the existing `lws:binaryKey` triple — `LwsResource` already carries `binaryKey` independently of the path, so nothing else changes. That fixes case collisions, the file/directory collision, Windows-illegal characters (`:`/`?`/`*` currently throw `InvalidPathException` out of the write transaction), reserved device names (`CON`, `NUL`), `NAME_MAX` overflow from long slugs, and makes the content-addressed write-then-commit of H13 possible.

## H15 — Container ETags are computed two incompatible ways, so conditional writes on containers are impossible — **FIXED**
**`core/ResourceService.java:152` vs `http/LwsResourceServlet.java:459-481`** · correctness/protocol · CONFIRMED

`read()` returns a container ETag recomputed from the rendered listing (`Etags.forModel(rep)`), and that is what reaches the wire. Every precondition check instead reads the *registry* copy via `service.stat(path)` — whatever `Etags.of(iri, modified.toString())` was persisted at creation (`:552`). The two are computed from different inputs and never reconciled. `LwsResource.withModified` (`:57-60`) copies `etag` through unchanged, so a container's stored ETag is **frozen at creation forever** even as membership changes.

**Impact.** `GET /c/` returns `ETag: "3f2a…"`. `DELETE /c/` with `If-Match: "3f2a…"` → 412, always. `PUT /c/` → 428 without `If-Match`, 412 with the ETag the server just gave you. The only way through is `If-Match: *` — the unconditional overwrite the 428 rule exists to prevent. And because `withModified` never refreshes the ETag, two consecutive POSTs into `/c/` leave the registry value byte-identical, so even a client that somehow learned it gets no lost-update protection.

**Fix.** Make one ETag authoritative. Simplest: have `create`/`put`/`delete` recompute and persist the container ETag whenever they bump `modified`, and have `read()` return the stored value. Cleaner: base the container ETag on a monotonically bumped version counter in the registry and use it in both places. Add a test that round-trips GET-ETag → If-Match DELETE on a container.

## H16 — TDB2's single global writer lock is held across an unbounded outbound HTTP fetch — **FIXED**
**`rdf/Tdb2RdfStore.java:51-59`; `auth/WacAclService.java:193-194`** · concurrency · CONFIRMED

`Txn.calculateWrite` calls `begin(WRITE)` **before** running the caller's lambda (verified in bytecode), and TDB2 permits exactly one writer. `ResourceService` calls `authorize(...)` *inside* every write lambda (`:190`, `:221`, `:239`, `:279`, `:318`, `:378`, `:439`). Under WAC that reaches `loadGroupDocument` → `RDFDataMgr.loadModel(docUri)` (`WacAclService.java:194`) — a synchronous HTTP GET to an operator-external host with **no read timeout and no body cap**. The 5-minute `groupCache` memoizes only successes, so a hanging host is re-fetched every request.

**Impact.** Any user with Control on one of their own resources adds `acl:agentGroup <http://slowloris.attacker.example/group>` (a public address, so `permits()` allows it) and then issues writes. Each takes TDB2's writer lock and blocks for the OS TCP timeout. **Every other write from every other tenant across the whole storage stalls behind it.** The read path has the same shape and additionally pins a TDB2 read transaction, blocking journal reclamation and driving on-disk growth.

**Fix.** Evaluate authorization *before* opening the transaction (the child-filter loop at `:148-150` already does exactly this, and says why), re-validating cheaply inside if TOCTOU matters. Independently, give the group fetch a bounded client (connect + request timeout, size cap — reuse `HttpDocumentLoader`) and negative-cache failures.

## H17 — An unreadable `./lws.properties` is silently ignored, starting the server in fully open mode — **FIXED**
**`LwsConfiguration.java:260-267`** · security · CONFIRMED

```java
Path file = Path.of("lws.properties");
if (Files.isRegularFile(file)) {
    try (InputStream in = Files.newInputStream(file)) { p.load(in); }
    catch (IOException ignored) { /* optional */ }
}
```

`Files.isRegularFile` already answers "does it exist?", so the catch cannot be an existence check — it only swallows real I/O failures. Every property then falls back to its default: `lws.owners` becomes empty ⇒ `isOpenMode()` true ⇒ `DefaultAccessPolicy.canRead/canWrite/canControl` all return `true` unconditionally. `lws.base-uri` also silently reverts to `http://localhost:8080`, so every minted IRI and every DPoP `htu` becomes wrong at the same time.

**Impact.** The failure mode is the *hardening* step: an operator does `chown root:root lws.properties; chmod 600` because it holds `lws.oidc.client-secret`, while the service runs as an unprivileged user. `AccessDeniedException` is swallowed and the storage comes up world-writable. The only signal is one INFO line and one easily-missed WARN.

**Fix.** Ignore only `NoSuchFileException`; for any other `IOException` (and `IllegalArgumentException` from a malformed `\u` escape) throw `LwsConfigurationException("Cannot read " + file + ": " + e)` so startup fails loudly. Same for the classpath stream.

## H18 — Reserved suffixes are not rejected at create time: `.meta` mints permanently unreachable resources — **FIXED**
**`core/ResourceService.java:597-610`** · correctness · CONFIRMED (reproduced against a live server)

The same root cause as C2, in its non-security half. `LwsResourceServlet.service` routes on suffix *before* resource dispatch (`:64` `.acl`, `:68` `.meta`, `:72` `/.lws`), but `chooseName` applies no reserved-name check, so `Slug: report.meta`, `Slug: .meta` and `Slug: .lws` all create registry entries no HTTP method can reach.

**Impact.** `POST /c/` with `Slug: report.meta` returns 201 with a `Location` that routes to the *linkset handler for `/c/report`*: `GET` 404s, `PUT` writes someone else's linkset, `DELETE` is 405 — the resource can never be deleted individually. Meanwhile `GET /c/` still lists it with its media type and size, and its blob counts against `lws.quota.max-bytes` unreclaimably except by recursively deleting the parent. `Slug: .meta` permanently shadows the container's own linkset IRI.

**Fix.** Same as C2 layer 1 — one shared reserved-suffix predicate consulted by `chooseName` and `put()`.

## H19 — WAC delete notifications authorize against the parent container — **FIXED**
**`notifications/NotificationEmitter.java:72`** · security · CONFIRMED

```java
if (event.kind() == ActivityKind.DELETE) {
    String parent = parentIriOf(event.iri());
    return parent == null || resources.canRead(subscriber, parent);
}
```

Read permission on the *container* is accepted as read permission on the deleted *child* — not the same thing under WAC, where each resource may carry its own ACL. Create/Update take the correct path (`:76`). The obvious refutation (the child's ACL is already gone, so the parent fallback is equivalent) does **not** hold: `LwsComponents.java:130` registers the emitter *before* `:136` registers the ACL-cleanup listener, and `ResourceService` dispatches synchronously in registration order.

**Impact.** `/data/` is public-read; `/data/patient-9912-diagnosis` has a restrictive ACL. An attacker subscribes to `/data/`. Creates and updates of the private child are correctly suppressed, but on delete the attacker receives `{"type":"Delete","actor":"<clinician WebID>","object":{"id":"…/patient-9912-diagnosis"}}` — learning the resource existed, its full IRI, who deleted it, and when. The `parent == null ||` clause is additionally **fail-open** when `Iris.toPath` returns null.

**Fix.** Capture the authorization decision before the resource is removed (evaluate `canRead(subscriber, iri)` just before the delete transaction and carry the allowed-subscriber set on the event). Remove the `parent == null ||` fail-open.

## H20 — Every authenticated request creates an unused 30-minute Shiro session — **FIXED**
**`auth/AuthenticationFilter.java:77-87`** · reliability · CONFIRMED (measured)

The filter builds a `Subject` and calls `subject.login(...)` per request and never calls `logout()`. `ShiroSupport` builds a bare `DefaultSecurityManager`, so `DefaultSubjectDAO` + `DefaultSessionStorageEvaluator(sessionStorageEnabled=true)` apply: `login()` → `save(subject)` → `mergePrincipals` → `subject.getSession()`, creating a native session in a `MemorySessionDAO` with a 30-minute global timeout. Measured against the project's own shiro-core 2.2.0: 500 logins left 500 entries in `getActiveSessions()`. Nothing in `src/main` ever reads the Subject back — no `SecurityUtils.getSubject()`, `hasRole` or `isPermitted` — so these sessions are pure waste, and `LwsRealm.doGetAuthorizationInfo` is dead code (L11).

**Impact.** `did:key` credentials are self-issued and need no registration, so anyone can mint an unlimited stream of valid credentials offline. 500 req/s of distinct did:key JWTs for ten minutes leaves ~300,000 live `SimpleSession` objects pinned for the full timeout — hundreds of MB of unreclaimable heap plus an hourly O(n) validation sweep — with no authorization needed and no request ever having to succeed.

**Fix.** Disable session storage: `((DefaultSessionStorageEvaluator) ((DefaultSubjectDAO) sm.getSubjectDAO()).getSessionStorageEvaluator()).setSessionStorageEnabled(false)`. (Setting `sessionCreationEnabled(false)` on the builder instead makes `mergePrincipals` throw `DisabledSessionException` — not a substitute.) Given nothing consumes the Subject, the cheaper fix is to drop the per-request `login()` and the Shiro dependency entirely.

## H21 — JSON Merge Patch on a multi-subject RDF resource destroys the entire graph and returns 204 — **FIXED**
**`core/ResourceService.java:321-332`** · correctness · **CONFIRMED** (reproduced 2026-08-26; was UNVERIFIED)

`patchMerge` round-trips through Jena's JSON-LD serialization: `:323` merges over `RdfIO.write(m, RDFFormat.JSONLD)`, `:326` re-parses, `:330` does `conn.put(iri, updated)` — a full graph replacement. Jena emits a flat node object only when the model has exactly **one** subject; with two or more it emits `{"@graph":[...]}`. Merging the client's members at the top level yields `{"@graph":[...],"http://schema.org/description":"d"}`; re-parsing makes the top-level object a *named graph* node, so RIOT logs "named graph data ignored" and drops every pre-existing triple, leaving only the patch member on a fresh blank node.

Two subjects is the **normal** shape — the repo's own tests PUT `<#it> schema:name "x"`, stored as the resource IRI plus its `#it` fragment.

**Impact.** `PATCH /profile` with `application/merge-patch+json` returns 204 with a new ETag; a subsequent GET returns a single triple on a blank node. The name and about triples are gone with no error surfaced, and `registry.put` records the new etag/digest so the loss is durable. The operation is advertised on every RDF resource via `HttpSupport.ACCEPT_PATCH`. The whole RDF branch is untested — `EndToEndTest.jsonMergePatch` patches a JSON *blob*, and every merge-patch in `OperationsConformanceTest` targets a `.meta` linkset.

**Fix.** Either normalize before merging (when the JSON-LD is `{"@graph":[...]}`, apply the patch to the node object whose `@id` is the resource IRI and to nothing else), or reject `application/merge-patch+json` on RDF sources with 415 and drop it from `ACCEPT_PATCH` — `JsonPatch`'s own javadoc already argues JSON-LD shape is not a stable pointer target, and the same argument applies here. Either way, add a test that merge-patches a two-subject RDF resource and asserts the pre-existing triples survive.

## H22 — Open-mode access grants are permanent and survive lockdown — **FIXED**
**`http/AccessServlet.java:115-134`; `core/AccessService.java:87-108`, `:191-227`** · security · UNVERIFIED (sweep)

`isController(principal)` is `!isAnonymous && resources.canControl(principal, storageRootIri())`, and `DefaultAccessPolicy.canControl`'s first clause is `config.isOpenMode()`. With the built-in default `lws.owners=""`, **every authenticated principal is a storage controller** — and `DidKeyValidator` hands out an authenticated principal to anyone who self-signs a JWT. Grants are then persisted and permanent: the constructor re-derives `hasGrants` on every restart, `grants()` evaluates all stored documents on every check and never consults the grant's creator, whether that creator is still a controller, or the document's `storage` field (L18). `validatePolicy` does not constrain `target` at all, so `target.value` may be the storage root, and `targetCovers` prefix-matches everything under it.

**Impact.** An operator brings the server up on the documented defaults to try it out, then follows the hardening step (`lws.owners=<alice>`, even switching to WAC) and restarts. `GrantAuthorizer` still returns true for the attacker on every IRI under the root — invisible in `lws.owners` and in every ACL, revocable only by someone who thinks to enumerate `/.lws/access-grants`.

**Fix.** Do not derive controller status from open mode: require an explicitly configured owner (or real `acl:Control`), and refuse grant issuance entirely while `isOpenMode()`. Validate at creation that each `target.value` and the document's `storage` are within `config.storageRootIri()`. At evaluation time re-check that the grant's creator is still a controller, or store an issuer epoch bumped when `lws.owners` changes. Log a startup warning naming the number of active grants.

## H23 — `If-Match` is evaluated in a different transaction from the write it guards (lost update) — **FIXED**
**`http/LwsResourceServlet.java:459-465`, `:472-481`, `:578-588`** · concurrency · CONFIRMED

`checkIfMatch` and `requirePutPrecondition` both resolve the current entity-tag through `service.stat(path)`, which opens and closes **its own read transaction** (`ResourceService.java:117-120`). The mutation then runs in a new, later write transaction (`put` `:216`, `patchSparql` `:274`, `patchMerge` `:313`, `patchJsonPatch` `:373`, `delete` `:427`), and nothing inside re-reads or compares the ETag. TDB2 serializes writers, so the store is not corrupted — both writes simply succeed and the second silently discards the first. `enforceLinksetPrecondition` has the identical shape, as does `LinksetService`'s whole read-modify-write (M18).

**Impact.** Clients A and B both GET `/doc`, both receive `"v1"`, both `PUT` with `If-Match: "v1"`. Both pass the precondition before either enters `rdf.write`. Both commit. B silently overwrites A, and A receives 204 believing its update landed under a valid precondition — exactly the outcome optimistic concurrency exists to prevent. The suite has no concurrent test at all (`grep -rn 'ExecutorService|CountDownLatch|Thread' src/test/java` finds only `Thread.sleep` and one webhook latch).

**Fix.** Pass the raw `If-Match` value into `ResourceService.put/patch/delete` and compare it against `registry.find(conn, iri).etag()` **inside** the `rdf.write` callback, throwing 412 there — a genuine compare-and-swap under TDB2's writer lock. Do the same in `LinksetService`. Add a concurrency test: N threads GET the same ETag then PUT with it; assert exactly one 204 and the rest 412.

## H24 — ACL and linkset cleanup runs post-commit and is silently swallowed, so a re-created path resurrects the old ACL — **FIXED**
**`core/ResourceService.java:440-449`, `:621-631`** · correctness/security · CONFIRMED

`delete()` commits the registry and content removal first, then fires events (`events.forEach(this::emit)` at `:449`), and `emit` wraps every listener in `catch (RuntimeException e) { log.warn(...) }`. The two listeners that erase a deleted resource's access-control state are exactly these: `WacAclService.onResourceEvent` → `deleteAclFor` (`:243-252`, which swallows its own exception too) and `LinksetService.onResourceEvent` (`:175-181`). Each opens its own separate write transaction.

**Impact.** Alice deletes `/data/report`, whose ACL granted Bob Read+Write. The delete commits and returns 204; the ACL-cleanup transaction then fails (store contention, or the JVM is killed between commit and cleanup) — only a WARN is logged. Alice later PUTs a new, private `/data/report`. `WacAclService.resolve` finds the stale `<base>/data/report.acl` first, and an own-ACL outranks container inheritance, so **Bob silently retains read+write on a resource he was never granted access to.**

**Fix.** Delete the ACL graph and linkset row inside the same `rdf.write` unit as the registry delete — both are plain RDF operations on the same store and can take the caller's connection. Keep the post-commit event fan-out for genuinely external effects (notifications, index), where a listener failure may stay non-fatal.

---

# Medium findings

Grouped by area. All CONFIRMED unless marked.

### Authentication

| ID | Location | Issue |
|---|---|---|
| **M1** | `auth/SamlValidator.java:242-245` | `firstChild` is `getElementsByTagNameNS` — a *descendant* search, not a child scan. An assertion nested in `<saml:Advice>` supplies `Issuer`/`NameID`/`Conditions` to the outer one. Replace with a real child scan that skips `Advice`. |
| **M2** | `auth/SamlValidator.java:142-193` | Four fail-open paths: `withinValidity` returns true when `<Conditions>` is absent; `audienceOk` returns true when `Conditions` is absent **and** when it contains zero `<Audience>`; `SubjectConfirmationData/@Recipient` is only *read* into `clientId`, never compared to this server; `@Method` is never checked for the bearer method. No assertion-ID replay cache. Require `<Conditions>`; never treat absence as success. |
| **M3** — **FIXED** | `auth/LwsOpenIdValidator.java:133-139` | The trust `ASK` leaves `?svc` free with no path back to the subject, so **any** node in the loaded graph typed `lws:OpenIdProvider` with the right endpoint satisfies it. Bind it: `<sub> did:service ?svc . ?svc a lws:OpenIdProvider ; …` with `setIri("subject", sub)`. Contrast `SsiCidValidator`, which correctly checks `sub.equals(doc.getString("id"))`. |
| **M4** — **FIXED** | `auth/LwsOpenIdValidator.java:162` | `OIDCProviderMetadata.resolve(new Issuer(iss))` compiles to `resolve(issuer, null, 0, 0)` — **infinite** connect and read timeouts, on the Jetty request thread. A hostile CID pointing at a hanging endpoint parks a thread per request. Use the 3-arg overload (≈2000/5000 ms) and cache failures. |
| **M5** — **FIXED** | `auth/SsiCidValidator.java:59` | The subject URL is dereferenced on **every** unauthenticated presentation with no cache and no rate limit (the OpenID path at least caches successes). The server becomes an unmetered HTTP reflector against an attacker-chosen target. Add a bounded Caffeine cache with negative caching. |
| **M6** — **FIXED** | `auth/DpopValidator.java:125-132` | `recordJti` runs *before* the `ath` check and before `validator.validate(accessToken)`, so anyone can fill the cache with self-signed proofs. Capped at `MAX_JTI = 100_000` with a 300s TTL, i.e. ~333/s before eviction starts dropping unexpired entries and re-enabling replay. Move `recordJti` after `ath`; size from the expected request rate; emit a metric on eviction. |
| **M7** — **FIXED** | `auth/AuthenticationFilter.java:66` | **No CORS support at all** — zero `Access-Control-*` headers anywhere. `Authorization` forces a preflight, which is answered with `Allow:` only, so browser apps can never authenticate cross-origin and `acl:origin` is unreachable. For an LWS/Solid-style server whose entire client story is browser apps, this makes the HTTP API unusable from the web. |

### Authorization and grants

| ID | Location | Issue |
|---|---|---|
| **M8** — **FIXED** | `core/AccessService.java:254` | `case WRITE -> actions.contains("modify") \|\| actions.contains("delete")` — the two ODRL actions collapse onto the single mode the server uses for *all* destructive operations, so each implies the other. A grant saying only `"action":["modify"]` authorizes `DELETE /alice/` with `Depth: infinity`. Add a distinct `AclMode.DELETE`, or thread the concrete operation into `AccessService.grants`. |
| **M9** — **FIXED** | `auth/DefaultAccessPolicy.java:29` | `publicRead` is presented as per-resource state but is **only** ever assigned from `config.publicReadDefault()` at creation and carried forward verbatim. No servlet, service, linkset relation or UI action can flip it. So with the documented default `lws.public-read=true`, an operator who *did* set `lws.owners` still has every resource world-readable and no API to change it. |
| **M10** | `core/AccessService.java:167` | Client-supplied access-request/grant `inbox` is POSTed to with no policy — the same SSRF as H6 via a second producer. Validate in `AccessService.normalize`. |
| **M11** — **FIXED** | `ui/BrowsePage.java:312-321` | `removeAcl` deletes a resource's ACL with **no `canControl` re-check**, unlike its sibling `saveAcl` (`:292-303`) and the HTTP path. The only gate is `aclBox.setVisible(canControl)` — a boolean captured once in the page constructor and frozen in the serialized page instance, so a user whose Control was revoked can still delete the ACL from a live page. Push the check down into `WacAclService.putAclFor`/`deleteAclFor`. |
| **M12** — **FIXED** | `ui/OidcLoginPage.java:46-47` | UI SSO builds the principal straight from the pac4j profile and **never calls `app().validator()`**, skipping the subject-trusts-issuer check that the token form on the very same page (`LoginPage.java:62`) and the whole HTTP API enforce. Two OIDC doors with different guarantees, and the weaker one is the default. |

### Resource engine and transactions

| ID | Location | Issue |
|---|---|---|
| **M13** — **FIXED** | `core/ResourceService.java:582-585` | `resolveType` ORs `pathIsContainer` with the `Link: rel="type"` hint, so `PUT /foo` with an `ldp:BasicContainer` link registers a CONTAINER at a slash-less IRI. `create` then builds `childPath = "/x/foo" + "bar"` = `/x/foobar`, whose parent is recomputed as `/x/` — children land in the wrong parent and the container lists zero members. Reject a CONTAINER hint on a non-slash path. |
| **M14** — **FIXED** | `core/ResourceService.java:226`, `:549-553` | PUT with a body on an **existing container** silently discards the body and returns 204 with a *new* ETag, so the client believes a new version was stored. Either reject with 409/415 (LDP's model) or actually store the non-containment triples — and don't bump `modified`/ETag when nothing is stored. |
| **M15** — **FIXED** | `core/ResourceService.java:603-608` | `chooseName`'s collision probe is an uncapped linear scan issuing one `ASK` per iteration, **inside the global write lock**. 10,000 POSTs with the same Slug cost ~50M ASKs and each late POST holds the exclusive writer for 10,000 queries. Cap at ~8 attempts then fall back to a random suffix. |
| **M16** — **FIXED** | `rdf/RemoteSparqlRdfStore.java:30-54` | `read` and `write` are literally the same method with **no transaction** — the javadoc concedes they "differ only intent, not isolation". But `ResourceRegistry.put` alone is `deleteSubject` + `conn.load` (two round trips), and `create`/recursive-delete chain five or more. On the documented `lws.sparql.mode=REMOTE`, a concurrent read between the two halves sees a spurious 404, and two concurrent POSTs pick the same name. Make each logical mutation a single `DELETE…INSERT…WHERE` request, or mark REMOTE experimental and refuse it without an acknowledgement flag. |
| **M17** — **FIXED** | `core/JsonMergePatch.java:58-62`, `core/JsonPatch.java:129-135` | No depth or size guard on JSON parsing, and `apply` is directly recursive. **Measured on this classpath:** depth 2000 (12 KB) succeeds; depth 4000 (24 KB) throws `StackOverflowError` during `read`. Being an `Error` it escapes every catch in the stack, aborts the response with no problem+json, and is reachable pre-authorization. Add a nesting-depth guard (≈64), bound the recursion, and catch `RuntimeException \| StackOverflowError`. |
| **M18** — **FIXED** | `core/LinksetService.java:92-116` | Linkset PUT/PATCH is a read-modify-write across two transactions with no compare-and-swap, and `enforceLinksetPrecondition` adds a *third*. Two clients with the same valid `If-Match` both pass and both write; the last one wins. Same fix as H23. |
| **M19** | `core/AccessService.java:104-106`, `:153` | The `hasGrants` volatile fast-path flag can be left `false` while grants exist, silently disabling **all** grant-based authorization. |
| **M20** — **FIXED** | `ui/BrowsePage.java:248-290` | The console calls `rs.put`/`rs.delete` directly, so the mandatory conditional-write rule — which lives only in `LwsResourceServlet` — is bypassed entirely. Two console users editing `/notes` silently lose each other's edits while the UI reports "Saved." (UNVERIFIED, sweep.) |

### HTTP layer

| ID | Location | Issue |
|---|---|---|
| **M21** — **FIXED** | `http/LwsResourceServlet.java:112-121` | One content-derived ETag is reused for **every** negotiated serialization (Turtle / JSON-LD / N-Triples / RDF-XML / TriG), violating RFC 9110 §8.8.1 — and the 304 is returned at `:115` *before* `Vary: Accept` is set at `:120`, so the 304 carries no `Vary` (RFC 9110 §15.4.5). A client that cached Turtle gets a 304 for a JSON-LD request. Mix the media type into the ETag and negotiate before evaluating `If-None-Match`. |
| **M22** — **FIXED** | `http/StorageDescriptionServlet.java:50` | The storage-description ETag is regenerated per request from a model containing **fresh blank nodes** each call (`StorageDescriptionService.java:75`, `:113`, `:225`), so `Etags.forModel` differs every time — verified: `40ec162e5e06c3d7` vs `d699cc4ca046b387` for identical content. Conditional GET can never return 304; every discovery poll re-transfers, and shared caches accumulate one entry per request. Hash `buildJson()` or skolemize the nodes. |
| **M23** — **FIXED** | `http/LwsResourceServlet.java:150-171`, `core/ResourceService.java:148-152` | Every container GET authorizes **all** members and hashes the whole membership model before slicing the requested page — pagination bounds only the response, not the cost. Page 1 of a 200,000-member container costs the same as page 200, and a crawler walking `rel="next"` repeats it 200 times. It happens even for a 304. Push pagination into the registry and derive the validator from cheap metadata. |
| **M24** *(fixed)* | `storage/FileSystemBinaryStore.java:54-57` | A data resource at `/a` (a file) and one at `/a/b` (needing `/a` to be a directory) collide: `Files.createDirectories` throws `FileAlreadyExistsException` → a permanent 500 instead of 409, and `delete` never prunes empty directories so it persists after cleanup. Fixed by H14's opaque keys; short of that, detect and return 409. |

### Bootstrap, TLS, configuration

| ID | Location | Issue |
|---|---|---|
| **M25** *(fixed)* | `JettyLauncher.java:187` | The bare launcher creates its `ServletContextHandler` without `setMaxInactiveInterval`, and jetty-session 12.0.33 defaults `_dftMaxIdleSecs` to **-1** — sessions never expire. The Spring path sets 30 minutes. The two bootstraps are documented as "line-for-line analogues", and it is the **intended production target** that is weaker: a crawler against `/app/*` accumulates sessions until the heap is exhausted. One line: `context.getSessionHandler().setMaxInactiveInterval(1800)`. |
| **M26** — **FIXED** | `tls/AcmeCertificateManager.java:195`, `:105` | The ACME **account** key and the TLS **domain private key** are written via `Files.newBufferedWriter(file)` with no permission attributes, and `tls/` is created the same way — mode 0644/0755 under a typical umask. Any local user reads the server's TLS private key. Create with `rw-------` / `rwx------`. |
| **M27** — **FIXED** | `LwsConfiguration.java:132-135` | `lws.sparql.mode=REMOTE` is accepted with blank, unvalidated query/update/gsp endpoints, producing an `RDFConnectionRemote` with no destination that dies later as an opaque Jena `ARQException` naming no config key — exactly what `LwsConfigurationException` exists to prevent. Validate them as required-when-REMOTE absolute URIs. |
| **M28** — **FIXED** | `JettyLauncher.java:86-89` | `HttpsRedirectFilter` is live from `server.start()` while `enableTls` blocks on the entire ACME order (up to several minutes for three domains), so every port-80 request gets a cacheable `301` to a port where nothing is bound. `enableTls` is also `throws Exception` and uncaught in `main`, unlike the renewal path. Install the filter only after the HTTPS connector starts; catch and retry. |
| **M29** — **FIXED** | `ui/LwsWebApplication.java:69-77` | **Wicket runs in DEVELOPMENT mode in the shipped jar.** `getConfigurationType()` is never overridden and no `wicket.configuration` init-param, system property or env var is set anywhere. Wicket's default is DEVELOPMENT, which sets `SHOW_EXCEPTION_PAGE`, a 1-second markup-polling thread, `stripWicketTags(false)`, and Ajax debug. This is not theoretical — the tracked `server.err` is captured stderr from a real `java -jar target/lws-server.jar` run showing Wicket's development banner. Any unhandled exception renders a full stack trace to an anonymous visitor. Override `getConfigurationType()` to `DEPLOYMENT` and set `setUnexpectedExceptionDisplay(SHOW_INTERNAL_ERROR_PAGE)`. |
| **M30** — **FIXED** | `ui/LwsSession.java:36-44` | `signIn` does not call `replaceSession()` (**session fixation**) and `signOut` does not `invalidateNow()`. All three sign-in routes go through this one method. After logout the Wicket page store still holds pages rendered while signed in, whose stateful links remain invokable. |

### Notifications

| ID | Location | Issue |
|---|---|---|
| **M31** — **FIXED** | `notifications/NotificationEmitter.java:49-77` | Delivery-time authorization runs synchronously on the **writer's** servlet thread, so `WacAclService.originAllowed` and `AccessService`'s ODRL `purpose` constraint read the *writer's* `Origin`/`LWS-Purpose` headers when deciding what a *subscriber* may receive. Both over- and under-delivery follow. Clear or replace `RequestContext` around the delivery check, or move fan-out off the request thread with an explicit context. |
| **M32** — **FIXED** | `notifications/SubscriptionService.java:115-135` | `activeMatching` calls `all()`, which does `conn.fetch(SUB_GRAPH)` — a **full materialization and re-parse of the entire subscription graph** — on every resource event, on the request thread. `delete … Depth: infinity` over 5,000 resources with 1,000 subscriptions is millions of transactions inside one HTTP request. Use a filtered SELECT, cache with invalidation, and hand listeners the event *list*. |
| **M33** — **FIXED** | `notifications/WebhookDispatcher.java:39-99` | Two-thread pool, unbounded queue, no rejection policy, no per-host limit, and a **blocking `Thread.sleep` backoff**: worst case ≈ 5×15s + 20s = **95 seconds of a worker per item**. Two slowloris inboxes pin both threads indefinitely and every other subscriber's notifications pile up. Bounded queue + drop-and-log, configurable pool size, per-host caps, and `ScheduledExecutorService` re-submission instead of sleeping. |
| **M34** — **FIXED** | `notifications/WebhookDispatcher.java:78-99` | Outcome-blind retry: permanent 4xx and deterministic failures (e.g. `HttpRequest.newBuilder` throwing `IllegalArgumentException` for a `mailto:` inbox, which `URI.create` happily accepts) are retried five times with 20s of sleep. Classify outcomes; retry only 5xx/429/transient I/O; deactivate on 410. |
| **M35** — **FIXED** | `notifications/HttpMessageSignatures.java:35-38` | `@authority` is built from `URI.getPort()`, which returns the *explicitly written* port — so an inbox of `https://inbox.example:443/hook` is signed as `inbox.example:443` while the wire `Host` is `inbox.example`. RFC 9421 §2.2.3 requires normalization, so a conformant verifier rejects **every** delivery as forged. `WebhookDeliveryTest` doesn't catch it because it rebuilds the base the same way. |
| **M36** — **FIXED** | `notifications/WebhookKeys.java:38-51` | The Ed25519 seed is written with default permissions and **non-atomically** (no `CREATE_NEW`, no temp+`ATOMIC_MOVE`; `writeString` truncates first). A local user who reads it can forge RFC 9421 signatures that verify against the published JWKS. A kill between truncate and write leaves a file whose decode throws a non-`IOException` that escapes the catch at `:54`. |
| **M37** — **FIXED** | `http/SubscriptionServlet.java:96-101` | Unauthenticated POST with no size cap and no `Content-Type` check, and `topics` accepts an arbitrarily long array — one request becomes N pre-auth read transactions, and every subsequent resource event walks that N-entry list in `covers`. Cap body size, require a JSON content type, cap topic count. |

### Persistence

| ID | Location | Issue |
|---|---|---|
| **M38** — **FIXED** | `rdf/RdfIO.java:27` | TriG is advertised as a supported **input** serialization, but `RdfIO.parse` reads into a `Model`, so Jena drops every non-default-graph quad with a one-time warning that never reaches the client. `PUT` returns 201/204 and the named-graph data is silently gone; the ETag is computed over the truncated model so the client cannot detect it. Make TriG output-only, or parse to a `DatasetGraph` and 400 on non-default-graph data. |
| **M39** — **FIXED** | `rdf/Tdb2RdfStore.java:42` | `read` creates a fresh connection and transaction per call with no way to reuse an open unit of work across component boundaries, and both authorizers do exactly one such call per check. A 1000-member container GET is 1000 transactions under owner mode and ~6000 under WAC at depth 5, all serialized on the request thread. Let `Authorizer.allows` accept an open `RDFConnection`. |

### Tests (medium — see the full assessment below)

| ID | Location | Issue |
|---|---|---|
| **M40** | `auth/SamlValidatorTest.java` | All five constructions pass `null` as `expectedAudience` and the helper emits no `<saml:Conditions>`, so `audienceOk` and `withinValidity` **both short-circuit in every test**. The `NotBefore`/`NotOnOrAfter` parsing and the whole `Audience` loop have zero executed lines, though `lws.saml.audience` is a documented key. |
| **M41** | `AccessGrantsTest.java:132-164` | Only `mediaType` and `purpose` constraints are exercised. The `dateTime` (expiry) and `client` branches are never reached, and every `target.value` is an exact IRI so the container-prefix branch of `targetCovers` never executes. Grant validity windows are the primary time-limiting mechanism and nothing verifies they work. |
| **M42** | `auth/WacAclServiceTest.java:45-56` | **No integration test ever boots with `lws.access-control=wac`.** All thirteen server-booting classes leave it at OWNER, so `LwsResourceServlet.handleAcl` and its `requireControl` gate are dead code as far as the suite is concerned — including the root-ACL protection and the `Link rel="acl"` header. A change dropping `requireControl` would be complete authorization bypass with no failing test. |
| **M43** *(fixed)* | `http/SubscriptionServlet.java:140-153` | `requireManage` consults `config.isOpenMode()`/`config.ownerWebIds()` instead of the configured `Authorizer`, so in WAC mode with `lws.owners` unset it **fails open** while every resource endpoint is correctly locked down. (UNVERIFIED, sweep.) |
| **M44** | `auth/LwsOpenIdValidatorTest.java:71-76` | `rejectsTokenSignedByKeyNotInJwks` mints with `keyID("foreign")`, so Nimbus fails to *find* a key and rejects before verifying anything — the signature-verification path the test name claims to cover never runs. Reuse `keyID("test-key")` on a foreign key. |
| **M45** | `FusekiSparqlEndpointTest.java:79` | `assertTrue(status >= 400)` cannot distinguish the failure it claims to cover: a read-only Fuseki simply doesn't mount `/lws/update`, so the response is a plain 404 — identical to a typo. There is no `read-only=false` companion test anchoring the URL, and `loopback` is untested. |
| **M46** | `SearchIndexTest.java:121` | An exact type-set assertion depends on a sibling method's DELETE, but JUnit's default order runs the mutating method **first**, so any early failure there cascades. |
| **M47** | `OperationsConformanceTest.java:42-46` | The conformance suite — the file COMPLIANCE.md leans on — runs in **open mode**, so its 435 lines assert no authorization outcome at all. |

---

# Low findings

Condensed; each was confirmed against the code.

### Auth (L1–L16)

`SsiCidValidator.java:93-112` accepts any `verificationMethod`, ignoring the `authentication` verification relationship · `JwsSupport.java:46-66` never cross-checks the JWS `alg` against the JWK type/curve, so an OKP **X25519** key is accepted as an Ed25519 signing key (confirmed by execution) · `LwsOpenIdValidator.java:98` seeds the signature-algorithm allow-list from the token's own header, making the key-selector check tautological · `LwsOpenIdValidator.java:96-102` cannot verify EdDSA-signed ID tokens even though the codebase has an Ed25519 verifier · `OutboundFetchPolicy.java:79-92` discards the vetted `InetAddress` so the fetcher re-resolves (DNS-rebinding TOCTOU), and `:94-105` omits CGNAT/benchmark ranges and 6to4/NAT64 IPv6 forms · `SamlValidator.java:58-76` loads trust anchors as bare public keys, discarding certificate validity dates · `Base58.java:40-48` returns one extra leading zero byte for an all-zero value, breaking round-trip · `DpopValidator.java:60-63` gives the jti cache a TTL measured from first use that is shorter than the `iat` acceptance window, allowing replay for up to `skewMs` · `AuthenticationFilter.java:176-184` returns `error="invalid_token"` for DPoP proof failures instead of RFC 9449's `invalid_dpop_proof`, and answers SAML2 rejections with a `Bearer` challenge · `AuthenticationFilter.java:113-117`, `:134` downgrade malformed/unknown `Authorization` headers to anonymous instead of 401 (`:120-122` is unreachable dead code) · `LwsRealm.java:45-57` is entirely dead code · `ShiroSupport.java:18-22` installs a VM-global singleton that `close()` never destroys, leaking a session-validation thread per component · `AuthenticationFilter.java:167-174` only ever emits `DPoP-Nonce` on the 401 challenge, costing a wasted round-trip every 5 minutes · `WacAclService.java:167-182` never invalidates the agentGroup cache on local group-document edits, delaying revocation by up to 5 minutes even though the class already implements `ResourceEventListener` · `WacAclService.java:76-81` accepts any subject with `acl:accessTo`/`acl:mode` as an authorization without requiring `rdf:type acl:Authorization`.

### Core and HTTP (L17–L34)

`Iris.java:101-124` — `.meta` survives `sanitizeSlug` (the non-security half of H18) · `AccessService.java:421-424` ignores the grant's own `storage` claim · `AccessService.java:505-514` — `dateTime` constraints silently never match unless the value is a UTC/offset instant, with no issuance-time diagnostic · `AccessService.java:39-41` — the class javadoc claims purpose/mediaType/type constraints make a grant inactive; the code implements all three as satisfiable · `ResourceService.java:125-126` resolves existence **before** authorization, and `stat()` is consulted with no authorization at all in OPTIONS and `requirePutPrecondition`, giving unauthenticated clients an existence oracle (404 vs 403) · `ResourceService.java:459-468` — recursive delete uses unbounded recursion and O(N) queries inside the exclusive write transaction · `ResourceService.java:470-480` — quota accounts only for non-RDF bytes and, when enabled, re-sums every `byteSize` triple on each binary write inside the write transaction · `ResourceService.java:574-575` strips the charset parameter and never restores it (mojibake on read) · `JsonPatch.java:51-59` catches only `JsonException`, so a non-string `op`/`path` or a `move` without `from` escapes as `ClassCastException`/NPE → 500 instead of 400 · `LinksetService.java:51-52` filters server-managed relations case-sensitively, letting clients inject conflicting `Type`/`Up`/`Anchor` links · `SearchIndexService.java:236-249` — `built` is a one-way latch, so a failed index-maintenance event leaves the type index permanently stale with no rebuild path · `HttpSupport.java:247-263` uses weak comparison for `If-Match` (shares `matchesEtag` with `If-None-Match`) · `LwsResourceServlet.java:472-481` never evaluates `If-None-Match` on writes (so create-only PUT is impossible) and treats `If-Match: *` on a missing target as satisfied · `HttpSupport.java:62-67` does not zero-pad the `Last-Modified` day-of-month (not a valid IMF-fixdate) · `LwsResourceServlet.java:95` echoes raw `IOException` messages — including filesystem paths — into problem+json detail on 500s · `LwsResourceServlet.java:637-638` ignores the request `Content-Type` on ACL PUT and parses any body as Turtle · `LwsResourceServlet.java:289` ignores `If-Range` · `LwsResourceServlet.java:332-346` runs OPTIONS with no principal and no authorization · `LwsResourceServlet.java:136-137` sends per-principal container listings with **no `Cache-Control: private`**, unlike `AccessServlet` and `SearchIndexServlet`, which correctly set `private, no-store` · `RdfFormats.java:104-111` ignores media-range specificity and `q=0` rejections · `RdfFormats.java:49` wires the `text/n3` alias to the **N-Triples** parser instead of `Lang.N3` · `AccessServlet.java:104-108` omits the mandatory `Allow` header on 405 · `HttpSupport.java:75` hardcodes a `Bearer`-only 401 challenge, contradicting the README's DPoP/SAML2 discovery claim.

### Notifications, storage, TLS, config (L35–L46)

`NotificationEmitter.java:56-57` drops `clientId` when reconstructing the subscriber principal, so client-constrained grants never apply at delivery · `SubscriptionService.java:158-176` opens a write transaction for **every** delivery including successful no-ops, and its read-modify-write is non-atomic on the REMOTE backend · `SubscriptionService.java:77-90` accepts an `expires` already in the past and returns 201 with `active=true` · `SubscriptionService.java:142-151` never reaps permanently deactivated subscriptions · `SubscriptionServlet.java:107-118` — collection GET applies **no authorization**: an anonymous caller is listed every anonymously-created subscription IRI · `WebhookKeys.java:71-76` has no key rotation (one JWK, one-hour cache, no overlap) · `WebhookDispatcher.java:117-120` — `close()` neither drains the pool nor closes the `HttpClient`, and races `rdfStore.close()` · `WebhookDispatcher.java:44` discards the submitted `Future`, swallowing bookkeeping exceptions unlogged · `FileSystemBinaryStore.java:60-66` never fsyncs, so durably committed metadata can point at unflushed bytes after power loss; `:69-71` has an unguarded `deleteIfExists` in `finally` that can mask the primary `IOException`, and crash-leftover `.lws-*.tmp` files are never reaped or counted against quota · `HttpsRedirectFilter.java:39-41` reflects the unvalidated `Host` header into `Location`, uses **301** instead of 308 (so clients rewrite POST to GET and drop the body), and never emits `Strict-Transport-Security` · `LwsConfiguration.java:199-211` — `validateTls()` checks neither the base-URI scheme nor `tlsPort != tlsHttpPort`; `:125` — a base URI without an explicit port silently listens on 8080 and its port is never range-checked, unlike every other port key; `:239-246` — `isLoopbackBaseUri` substring-matches `"::1"`, so any public IPv6 base URI ending in `::1` bypasses `lws.require-https`; `:194` — `acme.renew-before-days` has no upper bound, so a lead time ≥ the certificate lifetime re-orders every 12h until the CA rate-limits; `:573-575` — `/app` and `/callback` are not reserved, so resources created there are shadowed by the Wicket/pac4j filters · `AcmeCertificateManager.java:98` reuses a cached certificate without checking it covers `lws.tls.acme.domains`; `:109` never rotates the domain private key across renewals · `LwsComponents.java:242-251` runs four shutdown steps unguarded — a `FusekiException` from `sparqlServer.close()` skips both the dispatcher and the RDF store · `LwsServletConfig.java:46-64` accepts and validates `lws.tls.*` and then **silently ignores it** (TLS is bare-Jetty only) with no startup warning · `JettyLauncher.java:136-137` advertises the Jetty version in every response while the Spring path suppresses it; `:187` issues the session cookie with neither `HttpOnly` nor `SameSite` in **both** bootstraps · `tools/DidKeyTool.java:93-104` takes the Ed25519 private seed only via `argv` (visible in `ps`/shell history) and its fixed-pair argument loop silently discards options after a stray flag.

### Build, docs, tests (L47–L46 cont.)

`pom.xml:94-195` — `jakarta.json` API and implementation are **undeclared transitive** dependencies of the entire LWS JSON surface · `pom.xml:124-138` — unused `shiro-web` 2.0.5 ships beside `shiro-core` 2.2.0 with no `dependencyManagement` entry and no enforcer convergence rule (a fourth convergence incident after the three the POM already documents) · `pom.xml:124-129` — `jena-fuseki-main` is **compile-scope for a default-disabled feature**, dragging Fuseki, Prometheus, micrometer, TDB1, SHACL/ShEx and `commons-fileupload2 2.0.0-M4` (a milestone) into every deployment; the fat jar carries 159 third-party jars / 63.5 MB · `pom.xml:199-225` — surefire is unpinned · `pom.xml:12-28` — no reproducible-build timestamp · `pom.xml:197-226` — **no CI, no LICENSE, no SECURITY.md, no CONTRIBUTING, no dependabot, no dependency-vulnerability scan, no SBOM** · `README.md:86` says "Requires JDK 21+" but `maven.compiler.release=25` emits class file major 69, so JDK 25 is the real floor · `README.md:47-63` — the architecture tree omits the `tls/` and `tools/` packages and two `http/` servlets · `REVIEW-lws-server.md:39-105` is tracked and pushed, publishing eight still-unfixed vulnerabilities with file:line exploit pointers, with no SECURITY.md disclosure channel · `.gitignore:61` anchors `/lws.properties` to the repo root, leaving the equally-supported `src/main/resources/lws.properties` (OIDC secret, dev-login) untracked-but-committable; `:63-68` ignores smoke-test leftovers by **unanchored bare filenames** (`note.ttl`, `patch.rq`, `sub.json`, `locked.acl.ttl`, `cp.txt`, `*.err`) that match at any depth and will silently swallow future `src/test/resources` fixtures · `EndToEndTest.java:39` — **none of the 15 `createTempDirectory` sites is cleaned up**; `@TempDir` is used nowhere · `OperationsConformanceTest.java:430-433` — eleven classes bind-close-rebind an ephemeral port, leaving a TOCTOU window · `RemoteSparqlRdfStore.java:29-42` — no test exercises the REMOTE backend or the Spring Boot entry point · `AcmeSupportTest.java:82-102` — `dueForRenewal()` is an untested pure predicate although the test already builds the 90-day certificate it needs · `ui/LwsUiTest.java:64` — `LoginPage`, the WebID-impersonation dev-login form, has **no test**; the suite turns dev-login on and then bypasses the page by calling `signIn` directly · `core/Iris.java:101` — there is no `IrisTest`, and no test anywhere sends a traversal slug or path.

### Nits (19)

`DidKey.java:56` accepts uncompressed and hybrid EC point encodings, so one key has several did:key spellings that compare unequal in ACLs · `AuthenticationFilter.java:69-76` overloads a `null` return with two opposite meanings, disambiguated only by `response.isCommitted()` · `HttpDocumentLoader.java:63-66` swallows `InterruptedException` without restoring the interrupt flag · `ResourceService.java:582` — `resolveType`'s `isPut` parameter is dead · `SubscriptionServlet.java:94-100` accepts a POST body of any media type while advertising a specific `Accept-Post` · `RdfFormats.java:157`, `:186` use locale-sensitive `toLowerCase()` (breaks media-type lookup on a Turkish-locale JVM); `:97` has a dead tie-break, a dead wildcard branch and a duplicate alias · `NotificationEmitter.java:141-143` — `ActivityKind.as2Type()` is dead code, re-derived by string capitalization · `JettyLauncher.java:218-221` instantiates `SubscriptionServlet` twice where Spring registers one · `LwsServletConfig.java:152-155`, `:169-172` build throwaway pass-through filters for disabled pac4j registrations · `AccessGrantsTest.java:235` — `headers` takes a `contentType` it never reads and passes it through a tautological ternary · `pom.xml:183-187` — `spring-boot-starter-test` pulls a 17-jar unused stack; tests use only JUnit Jupiter (which arrives via `wicket-tester`) · `README.md:116-153` — `lws.system-prefix` and `lws.webhook.retry-backoff-ms` are live config keys documented nowhere in the README · `LwsConfiguration.java:157` — `lws.dpop.require-nonce` defaults to false (spec-conformant; the jti cache is node-local and size-bounded) · plus the four prior-review nits re-classified below.

---

## Protocol conformance

COMPLIANCE.md's "correctly oriented and largely complete" is defensible for the **surface**: lws+json containers with pagination, RFC 9264 linksets, RFC 9457 problem details, RFC 9530 digests, byte ranges, storage description, type index/search and ODRL grants are all really implemented, and `OperationsConformanceTest` does assert real protocol MUSTs (428/412 conditional replacement, 416 with `bytes */10`, `Depth: infinity` recursive delete, `Prefer` include/omit filtering) rather than only happy paths.

Several claims do not survive the code:

- **Conditional requests on containers are structurally broken** (H15) — the served ETag is content-derived, the stored one is IRI+timestamp.
- **`If-None-Match` is never evaluated on writes**, so create-only PUT is impossible (L28).
- **Discovery advertises only the OpenID suite** though README claims four are implemented, and advertises it unconditionally (`StorageDescriptionService.java:164-175`).
- **The RDF and lws+json storage-description representations are not the same graph** — they are hand-duplicated and disagree on capability detail and description-resource typing (`:61-155`).
- **`Link: rel="type"` is closed off entirely** — `HttpSupport.parseLinks:141-158` drops it and `LinksetService.SERVER_MANAGED` blocks it — which is the searchindex spec's *preferred* type source.
- **`GET /.lws/type-search` with no parameters enumerates every readable resource** (no mandatory type clause).
- **`POST` to a non-container returns 409** (with a spurious `Allow`) instead of 405.
- **Reserved suffixes are enforced on the request path but not on created child names** (C2, H18) — in WAC mode a privilege-escalation hole rather than a conformance nit.
- **RFC 9421 `@authority` is not normalized** (M35), so spec-conformant verifiers reject every notification.
- **No CORS** (M7), which makes the whole browser-client story unreachable.

---

## Test coverage assessment

The suite is unusually good for a project this size. It boots the real bare-Jetty stack over live TDB2 in a dozen integration classes, drives it with a real HTTP client, and verifies genuinely hard things: RFC 9421 signature bases re-derived and Ed25519-verified against the published JWKS (`WebhookDeliveryTest`), per-member listing authorization (`ResourceServiceListingTest`, `SearchIndexAuthzTest`), the full RFC 7386 Appendix A table, DPoP jti replay, WAC nearest-ACL override semantics. Assertions are mostly specific — exact status codes, exact `Content-Range`, exact ID sets — rather than smoke checks.

**The weakness is systematic, not local: authorization is essentially absent from the protocol layer's tests.**

- **Nine of the thirteen server-booting classes configure no `lws.owners`**, which puts `DefaultAccessPolicy` into open mode where every `canRead`/`canWrite`/`canControl` returns `true` before any policy code runs. `OperationsConformanceTest`, `EndToEndTest`, `SearchIndexTest`, `ContainerPaginationTest`, `QuotaTest` and `WebhookDeliveryTest` therefore never traverse an authorization decision at all.
- **No integration test boots with `lws.access-control=wac`**, so the entire `.acl` HTTP surface — including `requireControl` — is uncovered (M42).
- **No test ever sends a `DPoP` or `SAML2` `Authorization` header** (`grep -rn '"DPoP"' src/test/java` returns nothing), so two of the four credential paths exist only as isolated unit tests and the whole of `AuthenticationFilter.authenticateDpop` has zero executed lines.
- **The negative cases for the highest-risk code are missing entirely** — SAML wrapping, grant expiry, non-controller revoke, slug/path traversal, webhook inbox SSRF, concurrent conditional writes — and several of those paths are in fact defective.
- **Tests actively enshrine defects.** `WebhookDeliveryTest.java:107-113` posts an **anonymous** subscription with an arbitrary inbox and asserts **201**; `EndToEndTest.java:155-156` does the same with `http://localhost:1/inbox`.
- **Untested classes:** `FileSystemBinaryStore`, `RdfFormats`, `Tdb2RdfStore`, `RemoteSparqlRdfStore`, `Iris`, `LoginPage`, and the Spring Boot entry point. That is precisely why M38 (TriG quad loss), L-`text/n3`, H14 (key collisions) and the dead branches in `negotiate()` went unnoticed.
- **Hygiene:** all 15 temp data directories leak (`@TempDir` is used nowhere), and every server-booting class uses a bind-close-rebind free-port probe.

---

## Build, dependencies and repo hygiene

The POM is unusually thoughtful: the Spring Boot BOM is **imported rather than inherited**, and every skew the project has been bitten by (commons-lang3 3.17→3.18, split BouncyCastle, pac4j 6.0.2→6.1.2) is documented and pinned with a targeted `dependencyManagement` entry. The build was verified end-to-end offline: `mvn -o -DskipTests package` succeeds, produces `target/lws-server.jar` with `Main-Class: …JarLauncher` / `Start-Class: com.ebremer.lws.server.LwsServer`, and `PropertiesLauncher.class` **is** embedded — so the README's documented `-Dloader.main=…JettyLauncher` invocation genuinely works.

The weaknesses are in build *governance*, not build correctness: no CI, no LICENSE/SECURITY/CONTRIBUTING, no dependabot, no dependency-vulnerability scan or SBOM, no enforcer despite three documented convergence incidents (and a fourth shipping today: `shiro-core` 2.2.0 vs `shiro-web` 2.0.5), unpinned surefire, no reproducible-build timestamp, and a 63.5 MB fat jar largely because a **default-disabled** Fuseki endpoint is an unconditional compile dependency.

Two shipping defaults are outright wrong: **the Wicket console runs in DEVELOPMENT mode in the packaged jar** (M29), and **`lws.tls.*` is silently ignored by the Spring Boot entry point the README calls the default** (L58).

One disclosure concern: `REVIEW-lws-server.md` is tracked and pushed, publishing eight still-unfixed vulnerabilities with file:line pointers, and there is no SECURITY.md giving a private reporting channel. This document has the same property — consider keeping both out of a public repository until the P0/P1 items land.

---

## Status of the 24 prior-review findings (`REVIEW-lws-server.md`, 2026-07-09)

The source has not changed since that review (`c44d6ff` added all code; `33a3bb4` added only markdown), so all 24 remain open. Each was independently re-verified against the current code.

| Prior | Verdict | Now |
|---|---|---|
| 1 — webhook/notification SSRF | **REAL** | H6 |
| 2 — subscription creation unauthenticated | **REAL** | H7 |
| 3 — SAML signature wrapping | **REAL — critical** | C1 (PoC executed) |
| 4 — redirect-follow SSRF | **REAL, understated** | H5 — Jena uses `Redirect.ALWAYS`, not `NORMAL`, so HTTPS→HTTP downgrades are followed too |
| 5 — If-Match outside the write transaction | **REAL** | H23 |
| 6 — blob writes not rolled back with TDB | **REAL** | H13 — trigger is a registry/commit failure or crash, not `enforceQuota` |
| 7 — OIDC `aud` unverified | **REAL** | H2 (verified by execution) |
| 8 — unbounded request bodies | **REAL** | H12 |
| 9 — unsafe defaults (`public-read`, open mode) | **REAL** | M9 / H22 |
| 10 — DPoP nonce off by default | **Overstated → nit** | Spec-conformant; the jti cache is node-local and size-bounded |
| 11 — unbounded subject-document fetch | **REAL, understated** | H4 — the fetch happens *before* signature verification |
| 12 — grant evaluation cost | **REAL, mitigation understated** | M-perf — the `hasGrants` fast path means zero-grant storages pay nothing |
| 13 — ACL PUT has no conditional-write rule | **REAL** | Low |
| 14 — PATCH/DELETE accept unconditional writes | **REAL** | Low |
| 15 — Fuseki misconfiguration | **REAL but defaults safe** | Low — off / read-only / loopback by default; warning-only |
| 16 — Wicket CSP disabled | **REAL** | Low (and see H10/H11, which make it matter) |
| 17 — checked-in `lws.properties` enables dev-login | **WRONG** | The premise is false: `lws.properties` is gitignored (`.gitignore:61`) and untracked, and the tracked `lws.example.properties` sets `lws.ui.dev-login=false`. The *dev-login form itself* is still untested (L). |
| 18 — webhook key file permissions | **REAL** | M36 |
| 19 — unbounded in-memory type index | **REAL, mitigations understated** | Low |
| 20 — SPARQL guard completeness | **REAL — high, and concrete** | H8 — filed as a vague "suggestion"; it is an executable SSRF bypass via `FILTER EXISTS { SERVICE }`. The review's other two speculations here are **wrong**: `UpdateDeleteInsert extends UpdateModify`, and `UpdateData`/`UpdateDeleteWhere` carry no `Element`. |
| 21 — unknown auth scheme → anonymous | **REAL** | Nit |
| 22 — `ATOMIC_MOVE` has no fallback | **REFUTED** | Not a defect worth the fallback; the real blob problems are H13/H14 |
| 23 — jti consumed before later checks | **REAL** | Nit — but see M6, which makes the same code a replay concern |
| 24 — `close()` does not await termination | **REAL** | Low |

**Net:** 22 of 24 real, 1 wrong (17), 1 refuted (22). Three were materially *under*-stated (4, 11, 20). The prior review missed both criticals' full extent — it found the SAML issue but not the `.acl` collision, and filed the SPARQL bypass as speculation.

---

## Recommendations, in order

1. ~~**C2 — reserve `.acl`/`.meta`/`/.lws` at create time and move ACL graphs to `urn:x-lws:acl:*`.**~~ — **done**; see "Fixed: C1 and C2".
2. ~~**C1 — bind the SAML signature to the assertion whose claims are used.**~~ — **done**; see "Fixed: C1 and C2".
3. ~~**Close the credential-binding gaps as one change** (H1, H2, H3)~~ — **done**; see "Fixed: H1–H5".
4. **Give outbound HTTP one hardened, policy-checked, size-capped, redirect-validating client** and route *every* egress through it. The client exists and the auth/WAC paths use it (H4, H5, M4 **done**); still to route through it: **H6** (webhook/inbox delivery), **H9** (JSON-LD `@context`), **M5** (SSI-CID subject caching).
5. **Bound and re-order request handling** (H12): a `lws.max-request-bytes` cap enforced before the body is read, and authorization decided before the body is consumed.
6. **Make writes atomic** (H13, H23, H24, M18): content-addressed blobs with commit-ordered promotion; `If-Match` re-checked inside the write transaction; ACL/linkset cleanup inside the delete transaction.
7. **Fix container ETags** (H15) — conditional writes on containers are currently impossible.
8. **Harden the browser surface** (H10, H11, M29, M30): `nosniff` + `Content-Disposition` + type coercion on user content, Wicket's resource-isolation listener, deployment mode, session rotation, cookie flags. Ideally serve user content from a separate origin.
9. **Add a fail-closed production posture**: an `lws.profile=production` that refuses to start with empty `lws.owners`, flips `lws.public-read` to false, and refuses `dev-login` off-loopback — plus H17's loud failure on an unreadable config file.
10. **Close the authorization test blind spot**: an integration class booting with `lws.access-control=wac` and real owners, a DPoP/SAML HTTP path, negative SSRF cases, and a concurrent conditional-write test. Most of the findings above are cheap to pin once these exist.
11. **Add the missing project scaffolding**: CI running `mvn verify`, LICENSE, SECURITY.md (before the review documents stay public), dependabot, an enforcer convergence rule, and `dependency-check`/SBOM.

---

## Verdict

**Ship with fixes.** *(Updated 2026-08-26: both criticals are closed. The verdict paragraphs below
are kept as the record of the review's original judgement; the deployment advice that followed them
is superseded by the note at the end of this section.)*

The architecture is sound and much of the security engineering is genuinely above average for an early protocol implementation: fail-closed authorization defaults, no SPARQL injection, no XXE, correct DPoP mechanics, real RFC 9421 signatures, and a config layer that is in perfect sync with its own documentation. The problems are concentrated in four seams — namespace collisions between subsystems, claims that outrun the signatures that cover them, an ACID boundary that stops at TDB2, and one unguarded HTTP egress path — and each seam has a clean, structural fix rather than a pile of patches.

Until C1, C2 and H1–H12 are addressed, the defensible deployment is single-tenant owner mode behind a trusted reverse proxy with `lws.owners` set, `lws.public-read=false`, SAML disabled, notifications disabled, Fuseki off, and Wicket forced to deployment mode.

**Superseding note (2026-08-26).** C1, C2 and H1–H16 are fixed, along with H18, L17, M24, M25 and
M43. Both remotely reachable takeovers are closed, so WAC mode and the SAML suite are no longer the
disqualifiers they were. What remains before an untrusted network is the H17–H24 tail (a config file
that fails open when unreadable, delete notifications authorized against the parent, an unbounded
Shiro session per request), the medium/low findings, and the three defects **N1–N3** turned up while
fixing H16 — of which N1 (JSON-LD `@context` fetched inside the storage's single writer lock,
reachable without WAC) is the one an operator can trip over by following this project's own example
configuration.

See `TODO.md` for the prioritized work plan.

---

## Fixed: H1–H15 (2026-08-26)

All fifteen findings in the H1–H15 block are fixed. `mvn clean test` is green: **168 tests,
0 failures** (27 new). C1, C2 and H16–H24 remain open.

### H1–H5 — credential binding and outbound fetch

**New configuration** (all four added to `lws.example.properties`, keeping the key sync):

| Key | Default | Effect |
|---|---|---|
| `lws.audience` | this storage's IRIs | Accepted `aud` values for JWT credentials |
| `lws.audience.require` | `true` | Whether an absent `aud` is tolerated |
| `lws.token.max-lifetime-seconds` | `3600` | Lifetime cap for self-signed credentials (`0` = unlimited) |
| `lws.dpop.require` | `false` | Refuse plain `Bearer` outright |

**H1 — DPoP downgrade.** `DpopValidator.isSenderConstrained(token)` was added, and
`AuthenticationFilter` now refuses a `cnf.jkt`-bearing token under `Bearer` with a `DPoP` challenge
(RFC 9449 §7.1). The check runs *before* validation, so a downgraded token cannot even drive the
outbound subject-document fetch that validation performs. `lws.dpop.require=true` refuses `Bearer`
entirely. `SAML2` is unaffected. The false README claim was corrected.

**H2 — OIDC audience.** A new `AudiencePolicy` is consulted by all three JWT suites. A token whose
`aud` names something else is **always** refused, whatever the configuration; `lws.audience.require`
only decides whether an *absent* `aud` is tolerated. `azp` is deliberately left informational rather
than allow-listed — it is surfaced as the principal's client id and is where the ODRL `client`
grant constraint already reads from; the `aud` check is what closes cross-relying-party replay.

**H3 — self-signed suites.** `JwsSupport.temporalClaimsValid` replaced `notExpired`: it enforces
`exp`, rejects post-dated `nbf`/`iat`, and caps `exp - iat` at `lws.token.max-lifetime-seconds`.
did:key and SSI-CID also enforce the audience policy. The review's suggested `jti` replay cache was
**deliberately not implemented**: unlike a per-request DPoP proof, these are access tokens presented
on every request, so a single-use cache would break the suites. Audience binding plus a lifetime cap
addresses the actual finding (indefinite replay at arbitrary storages).

**H4 — pre-verification fetch.** `LwsOpenIdValidator.validate` was reordered: audience check →
JWKS/discovery → **signature verification** → subject-document fetch. An attacker must now hold a
token the issuer really signed before they can drive an outbound fetch. The fetch goes through the
hardened loader, failed trust lookups are negatively cached for 60s, and OIDC discovery — which used
the `resolve(Issuer)` overload with connect/read timeouts of **0, i.e. none** — now uses explicit
3s/5s bounds.

**H5 — redirect SSRF.** `HttpDocumentLoader` is built with `Redirect.NEVER` and follows redirects
itself, re-running `OutboundFetchPolicy.permits` on **every hop**, capped at 5. `DocumentLoader`
gained `loadRdf(url)`, and the two `RDFDataMgr.loadModel(untrustedUrl)` call sites — the OIDC subject
document and the WAC `acl:agentGroup` document — now go through it, so both inherit the per-hop
policy check, the 2 MiB cap and the 15s request timeout. (Jena's default client uses
`Redirect.ALWAYS`, which also follows HTTPS→HTTP downgrades.) The class javadoc's "residual risk"
note was narrowed to what remains: DNS rebinding between the check and the connect.

**Tests added** (16): redirect-into-a-blocked-address refused while an in-policy redirect is still
followed, and a redirect loop terminates (`HttpDocumentLoaderTest`); a `cnf.jkt` token refused over
`Bearer` while the same unbound token is accepted, and `lws.dpop.require` (`AuthenticationFilterTest`,
Mockito); cross-relying-party and absent-`aud` rejection for OIDC; wrong-audience, absent-audience
and century-long-lifetime rejection for did:key and SSI-CID; and `DidKeyTool --audience` round-trip.

**Note for operators — this is a breaking change.** With `lws.audience.require=true` (the default),
clients that do not set `aud` are refused. Mint with `DidKeyTool --audience <storage-base-uri>`, set
`lws.audience` to whatever your provider actually mints, or set `lws.audience.require=false` to
accept credentials that omit it (a wrong `aud` stays refused either way). Three integration tests
were updated to mint audience-bound tokens rather than to relax the setting.

### H6–H10 — notifications, SPARQL guard, JSON-LD, content serving

**New configuration** (six keys; `lws.example.properties` remains 58/58 in sync with the code):

| Key | Default | Effect |
|---|---|---|
| `lws.webhook.block-private-addresses` | `true` | Block delivery to private/loopback/metadata inbox addresses |
| `lws.webhook.allowed-hosts` | | Inbox hosts exempt from that block |
| `lws.subscriptions.allow-anonymous` | `false` | Allow unauthenticated subscription creation |
| `lws.subscriptions.max-per-subscriber` | `100` | Cap per subscriber (further creates get `429`) |
| `lws.subscriptions.max-lifetime-seconds` | `2592000` | Max/default subscription lifetime |
| `lws.jsonld.allowed-context-hosts` | | Hosts whose JSON-LD `@context` may be fetched |

**H6 — delivery SSRF.** A second `OutboundFetchPolicy` factory, `forDelivery(config)`, is threaded
into `WebhookDispatcher` and `SubscriptionService`, and into `AccessService` as a predicate (so
`core` keeps no dependency on `auth`). Inboxes are refused **twice**: as a `400` when the
subscription or access request is created, and again immediately before each delivery attempt —
the second check matters because the policy resolves DNS, so a host that was public at creation may
not be at delivery. Kept separate from `lws.fetch.*` deliberately: trusting an internal IdP to be
dereferenced is a different decision from being willing to POST notifications at an internal
address. The **read oracle** is closed too — `describe()` now strips `lws:failureCount` from the
client-facing representation (it is still tracked server-side for deactivation), so delivery no
longer reports whether an arbitrary internal URL answered. `active` is retained, but it only flips
after `lws.webhook.max-consecutive-failures`, so it carries no per-request signal.

**H7 — subscription limits.** Anonymous creation is refused unless
`lws.subscriptions.allow-anonymous` is set; subscriptions are capped per subscriber (`429` beyond
it) and topics per subscription (64); an absent `expires` is defaulted and a distant one capped to
`lws.subscriptions.max-lifetime-seconds`; a past `expires` is now a `400` rather than a
201-with-`active=true`. `requireManage` moved from the servlet into `SubscriptionService` and now
decides through the configured `Authorizer` (`canControl` on the storage root) instead of reading
`lws.owners` directly — it previously **failed open in WAC mode**, where `lws.owners` is consumed
only to bootstrap the root ACL. Open-mode behaviour is unchanged, since `canControl` short-circuits
there anyway.

**H8 — SPARQL guard traversal.** The single anonymous visitor was replaced by a `ServiceGuard` that
also walks *expressions*: `FILTER`, `BIND` and `LET`, plus a sub-select's `HAVING` and projection
expressions, recursing into the graph pattern that `EXISTS`/`NOT EXISTS` carries. `ExprFunctionOp`
is the only expression type that can hold a graph pattern, so covering it covers the whole
expression surface. Six bypass shapes are now regression-tested, including the two the review
executed live; an allow-listed host still works through the same nesting.

**H9 — JSON-LD contexts.** A `JsonLdSecurity` installs a Titanium `DocumentLoader` into RIOT's
context that refuses every remote `@context`. It is installed from `RdfIO`'s static initializer, so
it holds for any code path that parses RDF whether or not the server was wired up, and
`LwsComponents` widens it to the configured allow-list at startup. Permitted fetches are https-only,
size-capped (512 KiB), time-bounded and non-redirect-following. Inline `@context` objects — what
the server itself emits — are unaffected.

**H10 — stored XSS.** `HttpSupport.setContentSecurityHeaders` puts `X-Content-Type-Options: nosniff`
and `Content-Security-Policy: sandbox; default-src 'none'` on every non-RDF read, and forces
`Content-Disposition: attachment` for the active-content set (`text/html`, `application/xhtml+xml`,
`image/svg+xml`, XML). The stored media type is deliberately **preserved** rather than rewritten, so
clients that fetch the bytes still see the right type while browsers will not execute them in the
storage origin. Serving user content from a separate origin remains the stronger fix and is noted in
the README.

**Tests added** (6 methods): six `SERVICE`-in-expression bypass shapes plus an allow-listed control; a
blocked inbox refused at creation and anonymous subscription creation refused (`WebhookDeliveryTest`);
`failureCount` absent from the subscription representation, active content neutralised on read while
an inert type is untouched, and a remote `@context` refused rather than fetched (`EndToEndTest`).
`SubscriptionPurgeTest` was rewritten around a fixed clock, which also pins the new lifetime default.

**Note for operators — also breaking.** Loopback and private-address inboxes are now refused by
default; allow-list them with `lws.webhook.allowed-hosts` if you deliver to an internal consumer.
Anonymous subscription creation is off. Remote JSON-LD contexts are refused until you allow-list
their hosts. Four tests were updated to opt in explicitly rather than to weaken the defaults.


### H11–H15 — console CSRF, request limits, blob atomicity, container ETags

**New configuration:** `lws.max-request-bytes` (default 64 MiB; `0` disables). The example file
stays in sync with the code — 59/59 keys, both directions.

**H11 — CSRF.** `ResourceIsolationRequestCycleListener` is registered (Wicket 10's Fetch-Metadata /
Origin defence, which is *not* on by default), and all five destructive actions — the per-member
delete, the RDF/binary/ACL deletes and sign-out — are now POST forms instead of `<a href>` GET
links. A GET-triggered delete is reachable from any other page, and from link prefetchers and
mail/chat scanners, with no user action at all. Session cookies get `HttpOnly` + `SameSite=Strict`
in **both** bootstraps (in code for bare Jetty, in `application.properties` for Spring), and
`Secure` when the server itself terminates TLS. The bare launcher's session timeout was also set to
30 minutes, matching Spring — Jetty's default is *never expire* (this closes **M25**).

**H12 — request limits.** `HttpSupport.readBody` now takes a cap: it refuses on `Content-Length`
first, then reads one byte past the limit to catch a chunked body, and raises `413`. Every body-read
site is bounded — the resource servlet, ACL PUT, `AccessServlet`, and the two servlets that were
streaming straight into `Json.createReader` (`SubscriptionServlet`, `SearchIndexServlet`, the latter
having no authorization gate in front of it at all). Separately, POST/PUT/PATCH now run a
**pre-authorization check before the body is read**, so a request destined for 401/403 no longer
costs a full buffer first; it is deliberately permissive (it rejects only when denial is already
certain) and the authoritative check still happens inside the write transaction.

**H13 + H14 — blob keys and commit ordering** (fixed together, since the first enables the second).
Blob keys are now opaque and server-generated (`Iris.newBinaryKey`, a sharded UUID) instead of the
raw request path. That alone fixes cross-resource aliasing on case-insensitive filesystems, the
file-vs-directory collision, Windows-illegal characters and reserved device names. Because a new
version now goes to a key no reader can reach, `ResourceService` tracks `BlobChanges` per write:
staged keys are deleted if the transaction throws, superseded keys are deleted only after it
commits, and `deleteContent` records keys instead of unlinking them mid-transaction. A crash or
rollback can now leak an unreferenced blob — never leave a resource pointing at bytes that are gone.
Existing path-derived keys keep resolving (the key is stored per resource) and retire as resources
are rewritten, so no migration is needed.

**H15 — container ETags.** The persisted registry tag is now the single authority: a new `touch`
helper bumps `modified` **and** recomputes the tag wherever a container's membership changes, and
`read()` returns the stored value instead of hashing the rendered listing. Because the listing is
authorization-filtered, container responses are now sent `Cache-Control: private, no-store` — the
tag is a concurrency token for writers, not a validator a shared cache may key on.

**Tests added** (5): a cross-site form submit refused while a same-origin one succeeds
(`LwsUiTest`); oversized POST/PUT refused with 413 while an under-limit write succeeds; a container
ETag that changes with membership and round-trips through `If-Match` (stale → 412, current → 204);
two resources differing only in case keeping separate bytes across write and delete; and a data
resource coexisting with a same-named container. The last two would have failed on this machine
before the change. The existing `LwsUiTest` submits now carry `sec-fetch-site: same-origin`, which
is what a browser sends for a form the console itself rendered.

**Note for operators.** Console actions are POSTs now, so any bookmarked `?…-deleteRdf` style URL
stops working — that is the point. Cross-site requests to the console are refused outright. Request
bodies over 64 MiB are refused with `413`; raise `lws.max-request-bytes` if you store larger
objects through the API.

### Still open in this block

**H17–H24** are untouched, as are **C1**, **C2**, and the medium/low findings — except **M25** and
**M43**, which fell out of the H11 and H7 work respectively. **H16** is fixed; see the section
below.

---

## Fixed: H16 (2026-08-26)

`mvn -o clean test` is green: **174 tests, 0 failures** (6 new).

### What was wrong

`Txn.calculateWrite` calls `begin(WRITE)` before running the caller's lambda, and TDB2 admits one
writer for the whole dataset. `ResourceService` called `authorize(...)` *inside* every read and
write callback, and under WAC that reaches `WacAclService.matches → isMember → groupMembers →
loadGroupDocument`, a synchronous HTTP GET to whatever host an `acl:agentGroup` IRI names — an IRI
the requester writes into their own ACL. Every other write in the storage queued behind it.

### The shape of the fix

**The decision does not move; its inputs do.** An earlier draft memoised the authorization *answer*
outside the transaction and replayed it inside. That is a fail-open: `GrantAuthorizer` ORs in
`AccessService.grants`, whose grant scan, `dateTime`/`lteq` expiry and `mediaType` constraint are
local reads that today run on the writer's own snapshot, and `WacAclService.putAclFor` never passes
through `ResourceService` at all — so a grant revoked, an ACL tightened, or a media type changed
between the two points would have been invisible to the write it permitted. Every in-transaction
`authorize(...)` call is therefore left exactly where it was, and stays authoritative.

1. **`RdfStore.inUnitOfWork()`** (`rdf/RdfStore.java`), overridden in `Tdb2RdfStore` as
   `dataset.isInTransaction()`. Delegating to TDB2's own per-thread state rather than counting depth
   here matters two ways: it cannot be leaked by a missed decrement on a pooled Jetty worker (whose
   failure mode would be one worker refusing every outbound fetch for the life of the process), and
   it stays correctly `false` for `RemoteSparqlRdfStore`, which holds no transaction and no lock at
   all.

2. **`Authorizer.prepare(principal, iri, mode)`** (`core/Authorizer.java`) — a default no-op that
   resolves whatever an `allows` call for the same arguments would otherwise fetch. `WacAclService`
   overrides it as `allows(...)` with the answer thrown away: evaluating rather than reimplementing
   the traversal means it cannot drift from the real decision, and it warms exactly the documents
   that decision reaches, short-circuit included. `GrantAuthorizer` delegates; `OwnerAuthorizer`
   inherits the no-op, so a non-WAC deployment pays nothing.

3. **`ResourceService` warms before each transaction** — `read`, `create`, `put`, all three `patch`
   flavours and `delete`. `put` warms both `(iri, WRITE)` and `(parentIri, APPEND)` because which one
   applies is only settled inside the transaction. A recursive `delete` enumerates the subtree in a
   read transaction (which takes no writer lock) and warms each member, so the per-descendant check
   the javadoc promises is preserved verbatim.

4. **`WacAclService` refuses to dereference an external group document while a transaction is open**,
   logging at `WARN`. A refusal can only ever *narrow* a decision: the group fails to match that one
   authorization and every other authorization in the ACL still gets its chance.

5. **A failed load is no longer recorded as a membership fact.** `groupMembers` used to cache the
   empty model returned by a failed fetch into the 5-minute `groupCache`, so one failure denied every
   member of a legitimate group, for every principal, storage-wide, for the full TTL. Resolved
   documents now go in `groupCache`; a document the remote host would not serve goes into a separate
   short-TTL `groupFailures` cache purely so an unreachable address is not re-fetched once per
   request. A refusal because a transaction is open, or because the fetch budget is spent, caches
   **nothing** — those are facts about the caller, not about the group.

6. **A per-decision fetch budget.** `allows` tries every authorization scoping the target and every
   `acl:agentGroup` on each, without short-circuiting on a non-match, so the fetch count is chosen by
   whoever wrote the ACL — and a requester with `acl:Control` over their own resource writes that
   ACL. `lws.wac.max-group-fetches-per-decision` bounds it.

7. **`HttpDocumentLoader` is bounded end to end.** A 20-second `TOTAL_BUDGET` now spans all redirect
   hops *and every response body*, enforced by waiting on the asynchronous exchange with an explicit
   deadline and cancelling it on expiry. `HttpRequest.timeout()` was never enough: measured against
   this JDK, a host that returns `200 OK` at once and then emits one byte every two seconds ran for
   the full 60-second drip under a **three-second** request timeout — with `BodyHandlers.ofInputStream`
   *and* with a buffering handler, so this is not a streaming-versus-buffering distinction as an
   earlier draft of this note claimed. `sendAsync(...).get(remaining)` plus `cancel(true)` cuts the
   same drip off at 3.0 s while leaving a prompt response untouched at 7 ms. The body handler was
   still changed to a size-capped buffering subscriber, so that the cap is applied as the body
   arrives and the exchange is cancellable as a whole. All of this benefits the credential-validation
   paths equally.

**New configuration** (all three added to `lws.example.properties`, keeping the key sync):

| Key | Default | Effect |
|---|---|---|
| `lws.wac.group-cache-seconds` | `300` | How long a resolved `acl:agentGroup` membership set is reused |
| `lws.wac.group-failure-cache-seconds` | `30` | How long an unresolvable group document is left alone before a retry |
| `lws.wac.max-group-fetches-per-decision` | `8` | How many group documents one authorization decision may dereference |

**Tests.** `WacAclServiceTest` gains four cases: an external group document is never dereferenced
inside a transaction and *is* resolved by `prepare` beforehand; a failed fetch is not remembered as
an empty group; an unreachable one is not re-fetched per decision; and one decision cannot fetch
unboundedly many. The new `WriterLockAuthorizationTest` drives `create`, `put`, all three `patch`
flavours, `read` and a recursive `delete` under WAC through a loader that fails the test if it is
ever called while `inUnitOfWork()` is true. A sixth case pins `prepare`'s advisory contract: it must
absorb a decision that throws, because it runs ahead of the existence check and would otherwise turn
a `404` into a `500`.

**Note for operators.** Under WAC with an `acl:agentGroup` pointing at an *external* group document,
a decision made in the narrow window where the governing ACL changed after the warm-up — so the
group is neither cached nor warmed — now denies rather than fetching under the writer lock. It logs
`Refusing to dereference group document … while a store transaction is open`. A retry succeeds,
because the warm-up on the retry resolves the new group. Deployments in `OWNER` mode, and WAC
deployments whose group documents live in this storage, are unaffected.

**Deviations from the suggested fix.** REVIEW.md suggested hoisting `authorize(...)` ahead of the
transaction outright. That does not work: `OwnerAuthorizer.allows` returns `false` for any IRI with
no registry entry *before* consulting the policy, so a hoist ahead of
`registry.find(...).orElseThrow(notFound)` turns every `404` on a missing resource into a `401` —
seven assertions across five existing tests. Warming the inputs achieves the liveness goal while
leaving the ordering surface untouched by construction. No single-flight was added for concurrent
fetches of the same group IRI: the obvious implementation runs the fetch inside Caffeine's
`get(key, mappingFunction)`, which Caffeine documents as requiring short computations, and the
failure cache plus the per-decision budget already bound the repeat rate.

### Found while fixing H16 — new, not yet fixed

- **N1 · high · JSON-LD `@context` resolution runs inside the write lock.** `storeContent` calls
  `RdfIO.parse` at `core/ResourceService.java:633` inside the write lambda (from `create` and both
  `put` branches), and `patchMerge` calls it at `:392`. For JSON-LD that routes through
  `JsonLdSecurity.GuardedContextLoader.loadDocument`, a real HTTP GET with a 5 s connect and 10 s
  request timeout, recursively for nested contexts. It is the same defect as H16 by another path and
  needs **no WAC**: an operator who follows `lws.example.properties`'s own suggested
  `lws.jsonld.allowed-context-hosts=www.w3.org, schema.org` is one client `PUT` of
  `"@context":"https://www.w3.org/ns/activitystreams"` away from stalling every write while that host
  is slow. Hoisting the parse is awkward for `create` (the child IRI, which is the parse base, is
  only chosen inside the transaction by `chooseName`); the tractable fix is a context cache in
  `GuardedContextLoader` warmed by a discarded pre-parse outside the transaction.
- **N2 · medium · `blobs.write` runs inside the write lock.** `core/ResourceService.java:649`
  (and `:415`, `:467`) streams up to `lws.max-request-bytes` (64 MiB default) into the binary store
  while holding the global writer lock. On a local disk this is merely the most frequent long hold in
  the server; on an NFS/SMB data directory it is literally network I/O under the lock. `BlobChanges`
  (`:186-191`) already exists to make staging before the transaction safe, and `enforceQuota` needs
  only the byte length, which is known beforehand.
- **N4 · low · a blank node as `acl:agentGroup` makes every decision for that resource throw.**
  `WacAclService.matches` tests `st.getObject().isResource()`, which is true for a blank node, then
  passes `asResource().getURI()` — `null` — into the group cache lookup, which throws
  `NullPointerException`. Anyone with `acl:Control` over their own resource can write such an ACL and
  turn every request for it into a `500`. Pre-existing, and unchanged by the H16 work: `prepare`
  swallows it precisely so the warm-up cannot move the failure ahead of the existence check and turn
  a `404` into a `500` (pinned by `WacAclServiceTest.prepareIsAdvisoryAndNeverThrows`). The fix is one
  token — `isURIResource()` instead of `isResource()` — so the malformed authorization is skipped.
- **N3 · medium · an exception inside a nested inlined read tears down the outer write transaction.**
  Jena's `Txn.calc` catch block calls `onThrowable → abort(); end();` without checking whether it
  opened the transaction, so an exception raised inside a nested `Txn.calculateRead` — which is what
  `WacAclService.fetchAcl` and the local branch of the group lookup are when they run inside
  `ResourceService`'s write lambda — aborts the *outer* unit of work, after which `write()` can still
  return normally with half the work committed. H16's fix removes the network call that was by far
  the most likely source of such an exception, but the hazard itself remains.

---

## Fixed: C1 and C2 (2026-08-26)

`mvn -o clean test` is green: **206 tests, 0 failures** (32 new). Both criticals are closed, and with
them **H18** and **L17**.

### C1 — the signature is now bound to the assertion whose claims are read

The old code chose the claims-bearing element positionally (`getElementsByTagNameNS(...).item(0)`)
and then, independently, asked whether *any* `ds:Signature` anywhere in the document verified under
*any* trusted key. Nothing compared the two. `registerIdAttributes` marked `ID` on every Assertion,
which is what let a wrapped-away original's `Reference URI="#_a1"` still resolve and digest.

`validate` now requires all of the following before a claim is read:

1. exactly one `saml:Assertion` in the document, and exactly one `ds:Signature`;
2. that signature is a **direct child** of that assertion — a sibling walk, never
   `getElementsByTagNameNS`, so a signature nested in `saml:Advice` belongs to its own assertion;
3. its `SignedInfo` carries exactly one `Reference`, whose URI is **literally** `#<the assertion's
   ID>`;
4. that ID is unique in the document and `doc.getElementById` resolves it back to the same node;
5. the transform chain is the enveloped-signature transform plus at most one canonicalization.

Only the used assertion's `ID` is marked, and every claim is read by direct-child traversal
(`directChild`), which is finding **M1**.

**Two things the review's suggested fix got wrong, both settled by measurement.**
`assertion.isSameNode(context.getElementById(refId))` does not work: `DOMValidateContext` keeps its
own id map, and the dereferencer prefers `Document.getElementById` — so the suggested check both
fails closed on every honest credential (the context map is empty) *and* could pass while a
different element was digested. The code uses `doc.getElementById` plus the uniqueness scan instead.
And `org.jcp.xml.dsig.secureValidation` is not sufficient on its own: it rejects XSLT but **permits
both XPath dialects**, either of which can select a node-set unrelated to the element the URI names.
It is set explicitly to pin behaviour, but the transform allow-list is what actually closes that
door — and `-Dorg.jcp.xml.dsig.secureValidation=false` is a JVM-wide master switch a per-context
property cannot override, so nothing here relies on it.

**`audienceOk` was wrong too, and is fixed in the same pass.** SAML Core §2.5.1.4 makes the two
levels mean opposite things: `Audience` values within one `AudienceRestriction` are a disjunction,
but several `AudienceRestriction` elements are a **conjunction**. The old code returned true on the
first match anywhere, so an assertion the IdP restricted to us *and* to somebody else was accepted.
Configuring `lws.saml.audience` now also *requires* a restriction rather than checking one only if
present — which closes COMPLIANCE.md's "soft Conditions" caveat and changes nothing for a deployment
that leaves the key unset.

**Tests.** `SamlValidatorTest` grows from 5 to 18. Seven are the wrapping battery: the genuine
assertion re-parented into `saml:Advice`; a forged sibling ahead of the genuine one in a
`samlp:Response`; a signature over the enclosing `samlp:Response` (no assertion signed at all); the
genuine signature detached and re-parented onto the attacker's assertion; a whole-document
`Reference URI=""`; two signatures; and a wrapper reusing the genuine assertion's `ID`. Each
relocates a *genuine, untouched* signed assertion — which is why the pre-existing
`rejectsTamperedAssertion` could never catch this class. **Run against the pre-fix validator, four of
the seven authenticate — three as `https://attacker.example/profile#me` and one as the genuine
subject.** The other three were already refused, but incidentally, by a JDK default rather than by
anything the code asserted; they are pins, not reproductions. Six more cover the companions: the
`SubjectConfirmation/NameID` claim mis-attribution (M1's reachable case, which survives the
single-assertion rule), an XPath transform, the two audience semantics, a required restriction, and
a positive control that a single signed assertion inside an *unsigned* `samlp:Response` — the
commonest real IdP output — is still accepted.

**Note for operators.** The profile is deliberately narrow: a document with more than one
`saml:Assertion` is refused, which rules out a signed `samlp:Response` carrying unsigned assertions,
and a document with more than one `ds:Signature` is refused, which rules out a Response that signs
*both* itself and its assertion. A single signed assertion inside an *unsigned* Response — the
commonest real shape — is accepted, and there is a test pinning that.
There is no setting to relax it, because relaxing it is the vulnerability. TODO.md's interim
mitigation ("ship with `lws.saml.idp-certificates` empty") can be dropped — it was never carried out,
and the keys ship commented out, so the suite is already inactive by default.

### C2 — the ACL namespace is reserved, and ACL graphs left the public IRI space

**Layer 1 — one reserved-path predicate, consulted by the create path.** `core/Iris` gains
`ACL_SUFFIX`, `isAclPath` and `hasReservedSuffix`; `LwsConfiguration` gains `UI_PREFIX`,
`CALLBACK_PATH` and the composite `isReservedPath`. The split follows ownership: `Iris` owns the
suffixes (a fact about the IRI space, so `core` needs no dependency on `auth`), `LwsConfiguration`
owns the composite because the system prefix is configurable. `ResourceService` refuses a reserved
path with `409` in `chooseName` and at the top of `put`.

Three details are load-bearing. The check runs on the **sanitized, composed** path, because
sanitizing can *create* a reserved name — `Slug: x.acl-` and `Slug: .acl/` both collapse onto
`.acl` — and because the absolute reservations are invisible to a segment-only test (`Slug: app` at
the root composes `/app`). It runs **before** the de-duplication loop, which would otherwise turn a
reserved name into the legal-but-baffling `x.acl-2`. And it is a **refusal, not a rename**:
sanitizing the name away would answer a request a security control just denied with `201 Created`
and a `Location` header pointing somewhere the client never asked for. Matching ignores case and
covers the container form, on the principle that the guard must be a superset of what the router
diverts — reserving more than is shadowed costs a name nobody wants, reserving less is the finding.
`LwsResourceServlet` no longer attaches an `Allow` header to this particular `409`: `Allow` lists the
methods the target supports, and advertising `PUT` would invite a retry of the request just
permanently refused.

This is also **H18** (`.meta` minting resources every HTTP method routes away from) and **L17**
(`/app` and `/callback`, shadowed by the Wicket and pac4j filters).

**Layer 2 — `<resource>.acl` is now only an address.** `WacAclService.aclGraphName(target)` returns
`urn:x-lws:acl:<targetIri>`, matching the existing `urn:x-lws:admin` / `:linkset` / `:access`
convention, and `resolve`/`getAclModel`/`putAclFor`/`deleteAclFor` all use it. `aclIriFor` still
returns `<resource>.acl` and is used *only* for the advertised address — the `Link: rel="acl"`
header, the `Location` on a created ACL, and `handleAcl`'s routing. Since resource IRIs are always
built from the `http(s)` base, no request can name a graph in the new namespace.

Either layer alone closes the escalation. Both are here because layer 1 is what also fixes H18 and
the unreachable-resource class, and layer 2 is what makes the escalation structurally impossible
rather than merely guarded.

**A migration, because an existing store already holds the old graphs.** Two very different things
live at `<base>/*.acl`: ACLs this server wrote, and resources a client created there through this
very finding. The discriminator is whether the graph name is also a `ResourceRegistry` subject —
`putAclFor` is the only writer in the server that creates a named graph without one, while every
resource write pairs the graph and the registry entry in a single transaction and nothing removes an
entry while leaving its graph. So a graph *without* an entry is migrated, and a graph *with* one is
quarantined (logged, left alone, and inert under the new scheme) and never promoted. Deliberately
**not** decided from the graph's contents: an attacker writes `acl:Authorization` triples too — they
are the payload. A third pass drops `urn:x-lws:acl:<t>` graphs whose target has no registry entry,
which is how an ACL stranded by a WAC → OWNER → WAC round trip stops governing whatever is created
at that path next. In OWNER mode nothing is moved; the same scan runs read-only and reports what
*would* come alive if `lws.access-control` were switched to `wac`.

The ordering is the point: the migration runs **before** `bootstrapRootAcl`. So a store whose root
ACL was replaced through the old address gets the planted graph quarantined, which leaves the root
with no ACL, which makes bootstrapping rebuild it from `lws.owners` — **the upgrade itself restores
the owner the attack locked out**, which the finding says has no HTTP recovery path. That is pinned
by a test.

**No new configuration.** A key to un-reserve `.acl`/`.meta` would exist only to reopen the hole, and
a `migration=off` switch would not be the safe half of the pair either: an ACL can be *more*
restrictive than what it inherits, so skipping the migration can loosen access, not tighten it.

**Also fixed, found by attacking the above.** Three defects the adversarial pass turned up, two of
them introduced by this change. (1) The migration's discriminator was `registry.exists` on the graph
name, but only an *RDF* resource stores content in a graph at its own IRI — so a **binary** resource
planted at `/private/.acl` created a registry entry while leaving the server's real ACL graph
untouched at that name, and the migration then quarantined the legitimate ACL, dropping the container
to whatever an ancestor's `acl:default` allowed. It now discriminates on whether the entry could own
that graph. (2) `conn.fetch` of a graph that does not exist returns empty on TDB2 but **404s** on a
remote Graph Store Protocol service, so on the REMOTE backend the migration threw out of the
`LwsComponents` constructor and the server would not start — on exactly the stores the migration
exists for. A shared `fetchOrEmpty` absorbs it, which also fixes the same latent problem in
`WacAclService.fetchAcl`, where every inheritance lookup asks about a graph that usually does not
exist. (If a graph is quarantined and its target does turn out to need an ACL, the remedy is one
`PUT <resource>.acl` from any `acl:Control` holder — that path goes through `handleAcl`, not through
`ResourceService`, so the reserved-name refusal does not stand in its way.) (3) Pre-existing, and in the same blast radius: `BrowsePage.removeAcl` deleted an ACL with
**no authorization check at all** — its sibling `saveAcl` has one — so a revoked `acl:Control` was
still good enough to delete an ACL from a page instance held in a session, dropping its target to a
more permissive ancestor default. Whether a control is rendered and whether it may run are different
questions.

**Tests.** `ReservedNameTest` (10 cases) covers the predicate — including that it is a superset of
what the router diverts — and the service layer: `Slug: .acl` at the root and in a container,
`Slug: victim.acl` (the sibling-seizure variant), `Slug: report.meta` and `Slug: .meta` (H18),
`Slug: app`/`callback`/`.lws` at the root but *not* at depth, the slugs that only become reserved
after sanitizing, `PUT` at every reserved shape including the replace branch over a pre-seeded legacy
resource, and that ordinary dotted names and `%2Eacl` still work. `LegacyAclMigrationTest` (7 cases)
covers every branch of the migration including the root-ACL recovery. `WacAclServiceTest` gains two:
that an ACL is not stored at the address it is advertised at, and that the C2 payload written
straight into `<base>/shared/.acl` changes no decision at all.

**Note for operators.** Three breaking changes. (1) A resource can no longer be created or replaced
at a reserved name; `409` with a problem+json detail naming the reason. The realistic case is
uploading a file literally called `policy.acl` through the console. (2) An existing resource at such
a name becomes read-and-delete-only. (3) **ACL storage moves.** The client-facing address is
completely unchanged, but an operator who queries the store directly — the embedded Fuseki endpoint,
`tdb2.tdbquery`, a backup keyed by graph name — must look under `urn:x-lws:acl:` instead of
`<base>/*.acl`. The move happens automatically on the first WAC-mode boot and every step is logged at
`WARN`; read those lines, they are the audit trail of what was moved, quarantined and pruned.

---

## Fixed: M3 and M12 (2026-08-26)

`mvn -o clean test` is green: **209 tests, 0 failures** (2 new). Both are in the OpenID Connect
suite, and together they close the gap between its two doors.

### M3 — the trust query is anchored to the subject

The `ASK` that decides whether a subject trusts an issuer left the service node unbound:

```sparql
ASK { ?svc a lws:OpenIdProvider ; (did:serviceEndpoint|lws:serviceEndpoint) ?iss .
      FILTER( str(?iss) = str(?issuer) ) }
```

That asks "does this graph mention, *anywhere*, a provider pointing at this issuer?" — not "does
the subject claim it". Profile documents routinely describe other people: a `foaf:knows`, an
aggregator page, a shared or multi-subject document. Any of those makes a subject that claims
nothing inherit its neighbour's trust. The query now walks the link from the subject:

```sparql
ASK { ?subject (did:service|lws:service) ?svc .
      ?svc a lws:OpenIdProvider ; (did:serviceEndpoint|lws:serviceEndpoint) ?iss .
      FILTER( str(?iss) = str(?issuer) ) }
```

with `setIri("subject", sub)`. Both the CID v1 shape (`did:service`) and the plain LWS shape
(`lws:service`) are accepted, and they may be mixed. `SsiCidValidator` already did the equivalent
thing by checking `sub.equals(doc.getString("id"))`; this brings the OpenID suite in line.

The new `rejectsSubjectWhoseDocumentNamesTheProviderOnlyForSomeoneElse` serves a document whose
subject is an ordinary data resource that `foaf:knows` a genuinely trusted profile — and asserts, as
its own control, that the neighbour really is trusted, so the document does contain a matching
service and the anchoring is the only difference. Both new tests fail against the unbound query.

**Note for operators.** This is stricter, and the strictness is the point: the provider link must
start at the exact IRI the token's `sub` claim carries. A document that declares the service on
`<https://alice.example/profile>` while the token's `sub` is
`<https://alice.example/profile#me>` no longer establishes trust — it never was the subject's own
claim, and the loose query happened to accept it.

### M12 — the console login gets the same trust check as the API

`OidcLoginPage` built the principal straight from the pac4j profile, so browser SSO skipped the
subject-trusts-issuer step that the token form on the same page — and the whole HTTP API — enforce.
Two OpenID doors with different guarantees, and the weaker one was the default.

The fix is narrower than "run it through `app().validator()`", and deliberately so. pac4j has
already verified the ID token's signature, issuer, expiry, nonce and audience during the callback;
what it cannot know is whether the subject claims that issuer. Running the console's token through
`validate` would also re-apply the API's audience policy, which that token structurally cannot
satisfy: its `aud` is the console's OIDC client id, because the console is a *different relying
party*. Each door checks the audience appropriate to it, and pac4j has already checked the console's.

So `LwsOpenIdValidator.isTrusted` becomes the public `trusts(sub, iss)`, exposed through
`LwsCredentialValidator.openIdSubjectTrustsIssuer`, and `OidcLoginPage` consults it before signing
anyone in — dropping the pac4j profile and returning the user to the login page with a message
naming both the subject and the issuer if it fails. The method's javadoc states the precondition
that makes it safe to expose: the subject must come from an already-authenticated token, because
resolving it dereferences a URL that token supplied.

---

## Fixed: M17 and M37 — Batch E (2026-08-26)

`mvn -o clean test` is green: **218 tests, 0 failures** (9 new). This closes Batch E; the third H12
line in `TODO.md` is a recorded non-item (Jetty 12 has no request-body limit to set — the
application-level cap is the control).

### M17 — nesting depth is stack depth, so bound it before parsing

`jakarta.json` descends recursively, so a body's nesting depth *is* stack depth. Reproduced here:
`[` × 4000 — about 24 KB, far under any size cap — throws `StackOverflowError` inside the parser.
Being an `Error` it escapes every `catch` in the request stack, so the response is aborted with no
`problem+json` and no status at all, and on the endpoints that parse before authorizing an anonymous
client can do it.

The new `core/JsonLimits.requireBoundedNesting` runs **before** the parser sees the bytes: one
non-recursive scan counting brackets outside string literals, refusing anything past
`MAX_NESTING_DEPTH` (64). Because it never builds the structure, the overflow cannot happen rather
than being caught after the fact — which matters, since a handler for a blown stack runs on that
same exhausted stack and is not something to depend on. A `StackOverflowError` is nonetheless added
to each parse site's `catch` as a backstop, to turn one arriving by some other route into a `400`.

**The limit is measured, not guessed.** The concern with 64 was the one document this server
generates for itself — its JSON-LD projection of a stored graph, which `patchMerge` feeds back
through `read`. If that nested deeply, a legitimate resource would become un-patchable. It does not:
Jena flattens into `@graph` rather than nesting, and a 500-element `rdf:List` and a 500-link
blank-node chain measure **depth 3 and 4**. So 64 sits two orders of magnitude below the failure
point and an order of magnitude above anything real.

**Applied at every request-body parse site, not just the two the finding names.** `JsonMergePatch`
and `JsonPatch` are where the overflow was measured, but `AccessService.parseObject`,
`LinksetService.parseObject`, `SearchIndexServlet` and `SubscriptionServlet` reach the same parser
with the same untrusted bytes by the same route. Four instances of a fixed bug left in place would
have been a worse outcome than the one line each it costs to close them.

`JsonLimitsTest` pins the guard, the string-literal and escape handling (a `[` inside a string is not
structure), UTF-8 (no multi-byte sequence can be mistaken for a bracket, so no decoding is needed),
and that realistic documents are unaffected. It asserts on the *guard's own message*, deliberately:
with the guard removed but the backstop left in, the tests still passed — the distinction between
"refused before parsing" and "caught after overflowing" is the entire finding, so the test has to be
able to tell them apart. With both removed, a raw `StackOverflowError` escapes, as the review
measured.

### M37 — say what the subscription endpoint accepts, before spending anything on it

Anonymous subscription is a supported configuration, so `POST /.lws/subscriptions` may arrive with no
credential. It now requires a JSON content type before reading the body. The topic cap
(`MAX_TOPICS` = 64) was already in place from the H6 work; it had no test, and now has one, because
each topic costs a read transaction at creation and a walk per resource event afterwards.

`AccessServlet` had a private `requireJsonContentType` doing exactly this; it moved to
`HttpSupport` and both servlets share it, so the two cannot drift.

---

## Fixed: H17, H22, M9 and M9/prior-9 — Batch F (2026-08-26)

`mvn -o clean test` is green: **240 tests, 0 failures** (18 new). This closes Batch F, and with it
the "fail-closed configuration" theme: every finding in it had the same shape — an operator in the
development posture who was never told, because the development posture was the default and said
nothing.

### H17 — a configuration file that exists and cannot be read

`Files.isRegularFile` already answered "is it there?", so the `catch (IOException ignored)` after it
could only ever swallow a *real* failure. Every setting then fell back to its default, and the
defaults were the development ones. The failure this guards is the hardening step itself:
`chown root:root lws.properties; chmod 600` because the file holds `lws.oidc.client-secret`, while
the service runs unprivileged — and the storage comes up world-writable with one INFO line as the
trace. Now only `NoSuchFileException` is tolerated; anything else, including a malformed Unicode
escape, refuses to start. The read moved into `mergeOptionalFile` so it can be tested at all.

### H22 — a grant carries only the authority of the agent who issued it

**Reproduced end to end before fixing, and it was worse than the write-up.** On the shipped defaults
a `did:key` minted thirty seconds earlier POSTed itself an `AccessGrant` over the whole storage. The
storage was then hardened exactly as the README says — `lws.owners` set, `lws.public-read=false`,
restart — and the grant still returned `200` on read, `204` on overwrite, `201` on create and `204`
on delete, across the entire storage. It survived a further restart into WAC mode too. Issuing *new*
grants correctly stopped; the existing one was invisible in `lws.owners` and in every ACL.

Four changes:

1. **Open mode has no controller.** `DefaultAccessPolicy.canControl` loses its `isOpenMode()`
   disjunct — `canRead` and `canWrite` keep theirs. Open mode means no authorization is configured,
   which is a reason to permit reads and writes on a development box and not a reason to believe any
   agent was *entrusted* with the storage. `AccessServlet.isController` additionally requires
   `!config.isOpenMode()`, because that is the only test covering WAC as well, where the bootstrapped
   root ACL genuinely grants everyone Control. Grant issuance is refused outright in open mode, with
   a message that says why rather than "only a controller may".
2. **The issuer is re-checked at every evaluation.** `AccessService` takes a
   `Predicate<String> controllerPolicy` — the same shape as its existing inbox predicate, so `core`
   still depends on nothing in `auth` — wired to the **base** authorizer, never to the grant-aware
   one that calls it. An issuer dropped from `lws.owners`, or stripped of `acl:Control`, stops
   authorizing on the very next request.
3. **`storage` and every `target.value` are bounded at creation.** `storage` is an identity and is
   compared for equality; a target is a scope and must be inside this storage. Before this, a grant
   naming somebody else's storage was accepted and fully effective, and a policy with no `target` at
   all was accepted and silently inert.
4. **The stored grants are counted at startup**, along with how many are inert because their issuer
   no longer controls the storage. A grant appears in no owner list and no ACL; that line is the only
   place an operator inheriting a storage would ever see one.

**Per-issuer, not per-grant — and that is the design, not an optimisation.** Measured on a 200-grant
fixture, asking the authorizer per grant costs +29% under WAC and **+190% in owner mode** on a
decision that already takes ~10.7 ms. Only controllers can issue, so issuers repeat and are usually
a single WebID: asking once per distinct issuer costs under 1%. The memo is deliberately local to one
call — promoting it to the request would freeze an authorization answer for a whole request.

**The issuer epoch was considered and rejected.** A config-derived value bumped when `lws.owners`
changes is free and catches the H22 scenario, but under WAC `lws.owners` is consumed only to
bootstrap the root ACL; after that, controllers are whoever the root ACL says. An agent given
`acl:Control` by an ACL edit and stripped of it by another would never move the epoch — so it would
be blind in precisely the mode an LWS deployment cares about. It also over-fires: rotating one owner
out would void every grant every other owner ever made.

**A blocking new finding, fixed here because H22 cannot be closed without it.**
`WacAclService.bootstrapRootAcl` wrote a public-Read/Write/Control root ACL in open mode and then
returned early on every later startup, so configuring `lws.owners` afterwards did nothing at all —
a stranger still had `200` on read and `201` on write after the lockdown. It also defeats the issuer
re-check outright, since under that ACL every issuer still controls the storage. The development ACL
is now marked as one and is **rebuilt** the first time the server starts with owners configured. An
ACL the operator wrote carries no marker and is never touched — it is warned about, at every startup,
if it grants everyone `acl:Control`, because that is theirs to fix and silently destroying a
deliberate edit would be worse.

### M9 — `publicRead` was never per-resource, so it is gone

Confirmed and understated. The field was set from `config.publicReadDefault()` at creation and
carried forward verbatim by all eight write paths; nothing could flip it; and it was consulted at
exactly one site. Worse than a lie about the API, it was a **second lockdown-survival bug**: because
the value was *stamped* rather than consulted, resources created while `lws.public-read=true` stayed
world-readable after the operator set it to false. The H22 reproduction hit this too — it is why an
unrelated `did:key` could still read `/secret` after the hardening step.

The record component is deleted and `DefaultAccessPolicy.canRead` consults `config.publicReadDefault()`
directly. Runtime behaviour for a correctly-configured storage is unchanged; what goes is the
pretence, and the stale stamped value.

**It is not replaced with a real per-resource control**, and the alternatives were weighed rather
than waved off. A `.acl` in OWNER mode means a second, worse WAC. A privileged `.meta` relation puts
readability behind a `WRITE` gate, making write imply control — the inverse of what the finding asks
— and `Prefer: set-linkset` would let an ordinary content `PUT` flip it as a side effect. A header or
an `lws:publicRead` triple is invented surface that again lets content writers control their own
readability. All three mint a second control surface for something the spec-sanctioned access-grant
service already does properly: `assignee: foaf:Agent`, controller-issued, revocable, effective in
both authorization models. OWNER mode's job is single-tenant; per-resource is a grant, per-agent is
WAC.

### M9 / prior-9 — the development posture has to be asked for

**One key, not a profile.** `TODO.md` suggested `lws.profile=production`; that was rejected on the
reasoning behind the findings themselves. A profile that only tightens when it is set is a no-op for
exactly the operator it exists to protect — the victim in every one of these findings is the person
who did not know. Secure-by-default means moving the default, not offering an opt-in to safety. It
would also need an answer to "does the profile beat an explicit `lws.public-read=true`?", which is
config surface for no security gain.

So: **`lws.dev.open`**, default `false`, permitting exactly two development postures — an empty
`lws.owners`, and `lws.ui.dev-login` on a non-loopback base URI. Refused together with
`lws.require-https=true`, which is a development authorization posture and a production transport
posture asserted at once. `lws.public-read` now defaults to `false`. Developer sign-in is also gated
**per request**: refused from a non-loopback client, and refused outright when
`lws.behind-proxy=true`, since a fronting proxy makes the client address caller-supplied. Rendering a
control and letting it run are different questions, so the submit handler re-checks rather than
relying on the form being hidden.

**A fail-open bug in the loopback test, found while touching it.** `isLoopbackBaseUri` asked whether
the host *string* started with `127.` or contained `::1`, so the public address `[2001:db8::1]` and
the ordinary domain `127.example.com` both counted as loopback — and were therefore exempt from the
HTTPS requirement they most needed. It now classifies IP literals by what they are, and does not
resolve DNS: where a name points today is a fact about somebody's zone file, not about this
deployment, and honouring it would let a rebind switch the exemption on and off from outside.

**Sixteen test classes opt in**, and the choice of opt-in was made per class rather than uniformly:
seven that genuinely assert open-mode permissiveness set `lws.dev.open=true` (each with a comment
noting the class asserts no authorization outcome — finding M47, now greppable), and nine that never
traverse an authorization decision at all get an owner instead. Nothing was weakened.

**Note for operators.** This batch is deliberately breaking, in four ways. A storage with an empty
`lws.owners` **will not start**; set an owner, or `lws.dev.open=true`. `lws.public-read` now defaults
to `false`. Grant issuance requires a configured controller, and every existing grant stops
authorizing the moment its issuer stops being one — so **audit `/.lws/access-grants` before and after
upgrading**; anything issued while `lws.owners` was empty was issued by an agent nobody vouched for.
And a WAC store that ever booted with no owners has its root ACL rebuilt on the first start with
owners configured. One thing this does *not* fix: in such a store, pre-existing grants stay live
until that rebuild happens, because until then the issuer re-check passes for everybody.


---

## Fixed: H23, H24 and M18 — Batch G (2026-08-26)

`mvn -o clean test` is green: **257 tests, 0 failures** (17 new). This closes Batch G, and with it
the "make writes atomic" theme. H13/H14 were already done; what remained was the pair of findings
where the guard and the thing it guards lived in different transactions.

**Reproduced first, and it was not a narrow race.** `ConditionalWriteTest` was written before the
fix and run against the unfixed code. Eight clients that all `GET` a resource, all receive `"v1"`,
and all `PUT` with `If-Match: "v1"` produced **eight `204`s** — `[204, 204, 204, 204, 204, 204, 204,
204]` — on PUT, on merge-PATCH, and on linkset PATCH alike. Not "sometimes two writers slip
through": every writer won, every writer believed its precondition had held, and seven updates
vanished. The window is not a few microseconds wide, because the check does not merely happen early
— it happens in a transaction that has already *closed* before the writer lock is even taken.

### H23 / M18 — the comparison moved inside the transaction, not merely earlier

New `core/IfMatch`, a record over the raw header with `satisfiedBy(LwsResource)` and
`matches(String)`. It exists so that one comparison can serve two places without the two drifting —
`HttpSupport.ifMatchFails`, `HttpSupport.ifNoneMatchMatches` and the servlet's linkset
`If-None-Match` helper all delegate to it, and three hand-rolled dialects of entity-tag matching
collapsed into one. `ResourceService.put/patch/delete` and `LinksetService.put/patch/jsonPatch` each
gained an `IfMatch` overload; the old arities delegate with `IfMatch.NONE`, so no existing caller and
no existing test had to change.

The compare-and-swap itself (`ResourceService.requirePrecondition`) runs inside every write lambda,
**after `authorize`**. That order is deliberate: RFC 9110 §13.2.2 has a server ignore preconditions on
a request that would have failed anyway, so a caller who may not write here is refused for that
reason rather than being told through a `412` whether the resource exists and which tag it carries.

`LinksetService` needed more than a parameter. Its read-modify-write genuinely spanned three
transactions — the precondition read one, `readUserMetadata` a second, the store a third — plus a
fourth inside `resources.stat`. A new private `update(targetPath, ifMatch, UnaryOperator<JsonObject>)`
does the whole thing in one `rdf.write`, with the CAS inside it; `get` became a single read for the
same reason, since the resource metadata and the user links are both ingredients of the tag it hands
out and reading them apart could mint a tag for a state that never existed. Everything that can fail
on client input — parsing the patch, bounding its nesting — still happens before the transaction
opens, so nothing new runs under the writer lock. This also took a linkset PUT from five transactions
to one. *(Deviation from the suggestion: rather than giving `LinksetService` its own
`ResourceRegistry`, `ResourceService` gained `stat(RDFConnection, String)`. It keeps the service's
dependencies as they were and reads as what it is — the existing `stat`, on the caller's
transaction.)*

**A second lost update the write-up did not name.** `If-Match` against a resource that does not
exist used to be *ignored*: `requirePutPrecondition` is `stat(path).ifPresent(...)`, so a `PUT`
carrying a tag for a resource deleted in the window created it instead, and answered `201`. That is
the same lost update by another route — the version the client meant to replace is gone and it never
learns so — and RFC 9110 §13.1.1 makes the precondition false there, `If-Match: *` included.
`IfMatch.satisfiedBy(null)` is now false whenever a precondition is present. An unconditional `PUT`
still creates.

**The servlet keeps an early check, and it is now honestly advisory.** It runs before the request
body is read, which is worth keeping for the same reason `requireWriteBeforeBody` is: a doomed
request should not first cost a `lws.max-request-bytes` buffer. But it decides nothing. It was
reordered to sit *after* `requireWriteBeforeBody` so the servlet agrees with the transaction about
authorization outranking the precondition, and `handleDelete` — which has no body to bound — stopped
pre-checking altogether. That closes a small pre-existing oracle: an unauthorized caller could
previously distinguish "exists with tag X" from "does not exist" through `412`/`428` before ever
reaching a `401`. The `428` rule stays in the servlet, where it belongs: "replacing must be
conditional" is an HTTP policy, not a precondition, and `core` is deliberately free of servlet
concerns. Moving it is still M20's job.

### H24 — cleanup that commits with the delete, or not at all

New `core/ResourceCleanup` — `void onDelete(RDFConnection conn, String iri)` — registered through
`ResourceService.addDeleteCleanup` and invoked inside the delete's write lambda, per subtree member,
with no `try`/`catch`. `WacAclService` and `LinksetService` implement it instead of
`ResourceEventListener`, and `LwsComponents` registers them accordingly. The swallow was *removed*,
not relocated: keeping `WacAclService`'s inner `catch (RuntimeException e) { log.warn(...) }` would
have reproduced the bug inside the transaction.

Both cleanups take the caller's connection rather than opening their own. That is not a style
preference: on TDB2 a nested `rdf.write` joins the enclosing transaction and appears to work, while
`RemoteSparqlRdfStore.write` opens a fresh autocommitting connection and silently splits the delete
into two commits — exactly the divergence H24 is about, hidden behind a backend that looks fine in
the test suite.

The notification emitter and the search index **stay** in the post-commit fan-out, and each for a
decisive reason rather than convention. `NotificationEmitter` reaches
`WacAclService.fetchGroupDocument`, which refuses to dereference while `rdf.inUnitOfWork()` — every
`acl:agentGroup` subscriber would be silently denied — and it notifies about a write that could still
abort. `SearchIndexService` takes a JVM-level build lock that a concurrent reader may hold, so
calling it under the store's writer lock nests the two in opposite orders. Their effects are outside
the store; a failure there may still be non-fatal.

**A pre-existing bug fixed with it.** `deleteAclFor` was `conn.delete(aclGraphName(...))`, and most
resources have no ACL of their own. TDB2 treats deleting an absent graph as a no-op, but a remote
Graph Store Protocol service answers `404` — the same backend disagreement `fetchOrEmpty` already
absorbs on the read side. Harmless while the call was swallowed twice over; fatal once it aborts the
transaction, where it would have failed **every delete of an ACL-less resource** against that
backend. A `deleteGraphIfAbsentIsFine` helper now absorbs it, and `deleteAclFor` routes through it
too.

### Tests

`ConditionalWriteTest` (5) races eight writers at a PUT, a merge-PATCH, a DELETE and a linkset
PATCH, holding them at a latch so they all reach the server carrying the same tag, and asserts
exactly one `204` and the rest `412`. It also pins the create-branch refusal and that an
unconditional `PUT` still creates. `core/IfMatchTest` (7) pins the comparator itself, which four
call sites now share where three hand-rolled dialects used to live. `core/DeleteAtomicityTest` (5) pins the other half: a cleanup runs
inside the delete transaction (asserted via `RdfStore.inUnitOfWork`), every member of a recursive
delete is cleaned up, a failing cleanup aborts the whole delete and leaves both the metadata and the
binary content readable, and — the contract that did *not* change — a failing event listener still
does not. `OperationsConformanceTest.deletingAResourceRemovesItsLinkset` was strengthened from "the
`.meta` 404s afterwards" (which the resource being gone would satisfy on its own) to setting a real
user relation, deleting, re-creating the same path, and asserting the relation did not come back.

**A fail-open caught in self-review of this batch's own diff.** The first cut of `IfMatch.of`
folded a present-but-empty header into `NONE` via `isBlank()`. `If-Match:` with an empty value is
malformed, and the old hand-rolled comparator refused it with `412`; treating it as *no precondition*
would have answered a malformed precondition with an unconditional `PATCH` or `DELETE` — a fail-open
introduced by the fix for a lost update, in the same commit. Only a `null` header is `NONE` now, and
`IfMatchTest.anEmptyHeaderIsPresentAndMatchesNothing` pins it. Worth recording as the *shape* of
mistake to look for when one comparator replaces several: the merged version has to preserve the
strictest behaviour of every dialect it absorbs, not the most convenient.

**Note for operators.** One behaviour is deliberately breaking. `PUT` with an `If-Match` header
naming a resource that does not exist now returns `412` where it previously created the resource and
returned `201`; `If-Match: *` on a missing resource likewise. A client that sends `If-Match`
defensively on a create must send no precondition instead. Second, a `DELETE` whose ACL or linkset
cleanup fails now returns `500` and deletes nothing, where it used to return `204` and leave the ACL
behind — that is the point of H24, but it converts a silent inconsistency into a visible error.


---

## Fixed: H21, M13, M14 and M38 — Batch H (2026-08-26)

`mvn -o clean test` is green: **269 tests, 0 failures** (12 new). Four findings, one disease: a write
the server could not carry out was accepted anyway, answered `201`/`204` with a fresh entity-tag, and
the part it could not do was dropped on the floor. In every case the client's next `GET` is its only
evidence, and by then the previous version is gone.

**All four were reproduced before anything was changed**, and `ContainerSemanticsTest` was written
first and run against the unfixed code: 7 of its then-11 tests failed, and the 4 control cases (POST
with a container hint, default-graph-only TriG, SPARQL Update on RDF, merge patch on a JSON blob)
passed — so the suite discriminates rather than merely asserting the new behaviour. The class has
since grown to 14; the later ones came from the adversarial pass below and were likewise run against
the unfixed code first.

### H21 — merge patch over RDF, now CONFIRMED rather than UNVERIFIED

Measured against Jena 5.6 directly. For one subject Jena emits a flat node object; for two it emits
`{"@graph":[…]}`. Merging the client's members at the top level yields
`{"@graph":[…],"http://schema.org/keywords":"rdf"}`, which makes the top-level object a **named
graph** node. Re-parsed, a three-triple two-subject resource came back as **one** triple —
`[ <http://schema.org/keywords> "rdf" ] .` on a fresh blank node — and the server answered `204` with
a new entity-tag. Two subjects is not an edge case: it is a resource plus its own `#it` fragment, the
shape this repo's own tests PUT.

Refused with `415`, and dropped from `HttpSupport.ACCEPT_PATCH`. *(The review offered normalization
as the alternative; refusal was chosen because making it work asks the client to write its patch
against a different document shape depending on how many subjects the resource happens to have —
precisely the argument `patchJsonPatch`'s javadoc already makes for declining RDF. Offering merge
patch on RDF while refusing JSON Patch on RDF, for the same underlying reason, was incoherent.)*

**Note on conformance.** The LWS ED makes JSON Merge Patch the one PATCH format a server must
support; this server still supports it, on JSON resources and on linksets, and refuses it only on RDF
sources. That departure is recorded in `COMPLIANCE.md` rather than glossed. It is also now cheaply
reversible: with the M38 guard in place the failure mode is a `400`, not destruction, so normalizing
the `@graph` shape can be revisited without the original risk.

### M38 — a guard at the parser, which turned out to cover H21 too

The fix is one change in `RdfIO.parse`: parse into a `DatasetGraph`, refuse if any **named graph
carries data**, then reduce to the default graph. Reading a quad-bearing serialization straight into
a `Model` had Jena drop every non-default-graph quad with a one-time log line no client ever sees.

Four shapes were measured before choosing this, and the measurement is what made it safe:

| document | default graph | named graphs |
|---|---|---|
| plain Turtle | 1 triple | 0 |
| TriG with a `GRAPH` block | 1 triple | **1 — refused** |
| Jena's own 2-subject JSON-LD output (top-level `@graph`, no `@id`) | 2 triples | **0 — unaffected** |
| the H21 merged document | 1 triple | **1 (blank-node name, holding the 2 lost triples) — refused** |
| flat 1-subject JSON-LD | 1 triple | 0 |

The third row is the one that mattered: Jena's own round-trip output stays in the default graph, so
the guard costs no legitimate shape. The fourth is a bonus — the same guard turns H21's silent
destruction into a visible error even where merge patch is still reachable.

*(Deviation: the review's first option was "make TriG output-only". Refusing only the lossy subset
keeps TriG working as an input for documents that are genuinely a single graph, and the guard is at
the parser rather than in a format table, so it covers JSON-LD named graphs as well — a route the
format table would have missed entirely.)*

### M14 — a container's representation is its membership

PUT to an existing container with a body is `409`. A bodiless PUT — the idempotent "make sure this
exists" — returns `204` and changes **nothing**, including the entity-tag. That second half is not
cosmetic: bumping the tag for a write that stored nothing left a client holding the tag it had just
read, whose next conditional write would be refused `412` for a change that never happened.

### Ordering, settled while reviewing this batch's own diff

The three new refusals in `put` are ordered *this request contradicts itself* (400, M13) → *it
conflicts with what is stored* (409, type change) → *this method cannot do that here* (409, M14).
The first cut had `replaceContainer` return before `resolveType`, so an existing container quietly
absorbed a `NonRDFSource` hint that a missing one refused — the contradiction is a property of the
request, not of what happens to be stored at the path.
`ContainerSemanticsTest.aContradictoryHintIsRefusedOnAnExistingContainerToo` pins it.

### M13 — a type hint that contradicts the IRI it was sent to

On PUT the client names the IRI, so its shape and an explicit `Link: rel="type"` can disagree, and
the old code silently let the hint win: `PUT /foo` with `ldp:BasicContainer` registered a CONTAINER at
a slash-less IRI. Nothing downstream survives that — `Iris.parentPath` reads the string, not the
registered type, so `create` composes `/x/foo` + `bar` = `/x/foobar`, whose parent recomputes to
`/x/`. Children land in the wrong container and the one the client asked for lists nothing.

Refused with `400`, in **both** directions: a non-container hint on a path ending in `/` is refused
too. *(Slightly wider than the finding, which named only the container-on-slash-less case. One rule —
"on PUT, an explicit interaction model that contradicts the IRI's own shape is refused" — is easier
to state and to document than two, and the other direction was the same silent-substitution disease.
POST is exempt and regression-tested as such: it appends the trailing slash itself, from the type it
has just resolved, so the hint is never in conflict there.)* The guard went into `resolveType`'s
`isPut` parameter, which existed and had never been read — a nit the review had already noted.

**Note for operators.** Four deliberately breaking changes, all of them turning a silent `2xx` into
an error: `PATCH` with `application/merge-patch+json` on an **RDF** resource is now `415` (use
`application/sparql-update`), and RDF resources no longer advertise it in `Accept-Patch`; `PUT` with a
body to an existing **container** is `409`; a `Link: rel="type"` contradicting the IRI's shape is
`400`; and a request body carrying **named-graph** data — TriG with a `GRAPH` block, JSON-LD with a
named-graph node — is `400` instead of being stored with those quads dropped. A client relying on any
of these was already losing data; it just was not being told.

---

## N5 — Stored JSON depth is unbounded: many shallow patches compose into one document no reader can parse
**`core/LinksetService.java`, `core/JsonLimits.java`** · availability · **CONFIRMED** (reproduced 2026-08-26)

`JsonLimits.requireBoundedNesting` (added for M17) bounds the nesting of a **request body**, and only
that. A JSON Patch `add` at a deep pointer composes with the **stored** document, so a client that
may write a resource's metadata can grow the stored linkset's depth without limit — every individual
request comfortably inside the bound. Nothing checks the depth of the merged result before it is
stored, and `LinksetService.readUserMetadata` re-parses the stored literal with no bound at all.

**Reproduced.** Sixty rounds of a 60-level `add`, each request trivially small, produced a stored
linkset of **21,909 bytes** — and reading it back on a thread with an ordinary 512 KiB servlet stack
threw `StackOverflowError` inside `JsonParserImpl.getObject`. The probe is kept at
`scratchpad/N5-depth-amplification-probe.java`.

**Impact.** A permanent, stored denial of service on that `.meta` resource for *every* reader,
including the owner, from a handful of small authorized writes. `readUserMetadata` catches
`JsonException` and `IllegalStateException` but not `StackOverflowError`, so it surfaces as a `500`.
The same shape should be checked on any other path that merges client input into a stored JSON
document.

**Not introduced by Batch G**, which only moved where the linkset read-modify-write happens; the
guard was body-only from the start. Found by an adversarial agent probing the code Batch G had just
rewritten.

**Fix.** Bound the *result* before storing it — `JsonLimits.requireBoundedNesting` on the merged
document inside `LinksetService.update` — and add `StackOverflowError` to `readUserMetadata`'s catch
as the backstop for documents already stored, the same pattern M17 established at the parse sites.


---

## Fixed: M11, M20, M29 and M30 — Batch I (2026-08-26)

`mvn -o clean test` is green: **279 tests, 0 failures**. Batch I is the browser surface; H10 and H11
were already done, and what remained was the console's own posture.

### M29 — the packaged jar shipped in Wicket DEVELOPMENT mode

`getConfigurationType()` was never overridden and no `wicket.configuration` was set anywhere, so the
shipped jar ran with `SHOW_EXCEPTION_PAGE`, a one-second markup-polling thread, unstripped
`wicket:` tags and the Ajax debug window. Any unhandled exception rendered a full stack trace to
whoever triggered it. Now `DEPLOYMENT` by default, plus
`setUnexpectedExceptionDisplay(SHOW_INTERNAL_ERROR_PAGE)` as a second line for an operator who does
turn development mode back on.

*(Deviation from the suggestion, which was to set it unconditionally or from the two bootstraps:
`DEVELOPMENT` coming back from `super` is ambiguous — it means either "an operator asked for it" or
"nobody said anything" — so the override distinguishes them by looking for the operator's own words
in the three places Wicket looks. That keeps Wicket's existing switch working instead of taking it
away, and avoids minting an `lws.*` key that would be a second spelling for the same setting.)*

### M30 — session fixation, and a sign-out that did not sign anything out

`signIn` now calls `replaceSession()` before attaching the identity, and `signOut` calls
`invalidateNow()` instead of blanking a field. The second half is the one that is easy to
under-rate: clearing `principal` left Wicket's page store alive, holding pages rendered while signed
in, whose stateful callbacks were still invokable at their guessable URLs. All three sign-in routes
go through this one method, so it is the only place it has to happen.

### M11 — the ACL write checks Control, not just its callers

`removeAcl` had already gained a `canControl` re-check with H11's form conversion. What remained was
the finding's real point: pushing it down so no caller can skip it. `putAclFor`/`deleteAclFor` now
take a principal and refuse anyone without `acl:Control` on the target; the unchecked forms survive
as `putSystemAclFor`/`deleteSystemAclFor` for the writes the server itself owns — bootstrapping the
root ACL, the legacy migration, and test fixtures — deliberately named so a call site says which one
it is. Eleven test fixtures moved to the system form; the console and the servlet moved to the
checked one and kept their own earlier checks, which now bound the work done before the body is read
rather than being the only gate.

### M20 — a rule only one entry point enforced

The mandatory-precondition rule ("replacing MUST be conditional") lived in `LwsResourceServlet`, so
it governed the HTTP API and nothing else, and the console — which calls `ResourceService`
directly — was exempt. It now lives in `ResourceService.put`, which both entry points go through, and
the console passes the entity-tag of the version its page rendered. A second console user editing
from a stale page is told so, in words, instead of silently discarding the first user's work.

*(This is where Batch G's plumbing paid off: `put`/`patch`/`delete` already took an `IfMatch`, so M20
was a guard plus a call-site change rather than a signature migration. `core` still holds no servlet
or framework type — a status code is not one, and `LwsException` has carried them from here since the
beginning. The servlet keeps its own copy of the check purely to refuse a doomed request before its
body is read.)*

**One test had to opt in**, exactly as the convention says: `WriterLockAuthorizationTest` replaces
`/tree/leaf` and now reads the tag first, the way a real client does. Nothing was weakened to keep it
green.

### H10 (separate origin) — assessed and deliberately not done

The remaining H10 item is "serve user content from a separate origin", marked L and *(preferred
long-term)*. It is not a code change of this size: in LWS a resource's IRI **is** its address, so
moving user content to another origin either changes resource identity or introduces a redirect and
a second trust boundary, and it interacts with WAC's `acl:origin` and with certificate and DNS
provisioning an operator has to do. Left open with that reasoning rather than half-built. The shipped
mitigation from H10's first half — `nosniff`, `Content-Security-Policy: sandbox; default-src 'none'`,
and `Content-Disposition: attachment` on the active-content set — is what stands in for it, and it is
what makes the remaining item an improvement rather than a gap.

### The adversarial pass found four real defects in Batch H, all fixed here

Run read-only over the finished Batch H, and it earned its keep:

1. **M14 was fixed on one branch only.** `replaceContainer` guarded the replace path, while
   `storeContent`'s `CONTAINER` case — which every *create* route goes through — still never looked
   at `req.body()`. Creating a container with a body still discarded it and answered `201` with a
   fresh tag: the same defect one branch over, and my own README sentence ("a write that cannot be
   carried out is refused rather than partly performed") was broader than the code. The check moved
   onto the container, where it belongs, and covers PUT-create, POST-with-a-hint and
   POST-with-a-slash-Slug.
2. **A silent-loss path H21 had just redirected clients onto.** `patchSparql` runs the update against
   a `Model`, and Jena wraps that in a dataset that materialises a named graph on demand — so
   `INSERT DATA { GRAPH <g> {…} }` executed against a throwaway graph and the request answered
   `204`. **Measured**: one triple before, one after, no exception. Worse in the mixed case, where the
   default-graph half lands and the response carries a new and perfectly valid entity-tag over a
   partially-applied model. And the likeliest accidental trigger is a client naming *its own*
   resource IRI in a `GRAPH` clause, because this storage really does keep each resource in a named
   graph — just not the one the update sees. `SparqlUpdateGuard` now refuses any operation that names
   a graph (`GRAPH`, `WITH`, `USING`, graph management, `LOAD … INTO`), before the transaction opens.
3. **The capability document still advertised `merge-patch+json` for every RDF media type.**
   `StorageDescriptionService` was untouched by Batch H, so `/.lws/storage-description` — the document
   a conformance client reads to decide what to send — promised an operation the server had just
   started refusing with `415`.
4. **M13's POST exemption rested on a false claim.** The comment said POST is exempt because it
   appends the slash itself; in fact `create` derives `pathIsContainer` from the raw Slug, so
   `Slug: pics/` with a `NonRDFSource` hint had the slash win silently and the uploaded bytes thrown
   away. The trailing-slash half of the check now applies to POST too. The other half correctly does
   not: on POST a Slug without a slash plus a container hint is the ordinary way to create a
   container, not a contradiction — a distinction I got wrong on the first attempt and the test suite
   caught immediately.

**Note for operators.** Two behaviour changes beyond the console. A SPARQL Update naming any graph is
now `400` rather than a silent no-op — including one that names the resource's own IRI, which never
worked but never said so. And any caller replacing an existing resource must supply a precondition;
over HTTP that was already true, so only in-process callers are affected.


---

## Fixed: H19, M31–M36 and L39 — Batch J (2026-08-26)

`mvn -o clean test` is green: **296 tests, 0 failures** (17 new). This closes Batch J and P1 with it.

### H19 — the decision moved to before the delete, because it can no longer be made after it

Batch G made this worse before Batch J fixed it, and that is the interesting part. The original
finding notes that the emitter runs *before* the ACL-cleanup listener, so the deleted child's ACL was
still readable and the parent fallback was avoidable. H24 then moved ACL cleanup **into** the delete
transaction — so by the time the emitter runs, the child's ACL is gone, and even the "correct"
`canRead(subscriber, event.iri())` would now resolve through container inheritance and leak exactly
what the parent fallback leaked. Capturing the decision beforehand stopped being the tidier option
and became the only one.

New `core/DeleteAudience` — `Set<String> subscribersAllowedToKnow(String iri)` — consulted by
`ResourceService.delete` for every member of the subtree *before* the write transaction opens, with
the answer carried on `ResourceEvent.audience()`. The emitter's DELETE branch is now a membership
test and nothing else. The `parent == null ||` fail-open is gone: no captured audience means nobody,
which is the direction it had backwards — a `Iris.toPath` returning null (an IRI outside the base,
reachable on a reverse-proxy misconfiguration) used to turn the check off entirely.

*(The audience is a set of **subscription ids**, not WebIDs: an anonymous subscription has no WebID
and two subscriptions of one subscriber stay distinct. A subscription created between the capture and
the delivery is absent from the set and is not told — fail-closed.)*

### M31 — a subscriber's access decided from the writer's headers

Listeners run synchronously on the writer's thread, and `RequestContext` is a thread-local holding
that writer's `Origin` and `LWS-Purpose`. So `acl:origin` and ODRL `purpose` constraints were being
evaluated, for a *subscriber*, against whoever happened to make the change: a write from an
allow-listed app delivered notifications to subscribers an `acl:origin` rule existed to exclude, and
the identical write from anywhere else withheld them. Neither answer had anything to do with the
subscriber.

Every subscriber-authorization decision now runs with the context cleared and restored afterwards.
*Cleared* rather than substituted, deliberately: a webhook delivery genuinely has no origin and
declares no purpose, and `originAllowed` refuses when no `Origin` is present — the fail-closed
direction. Restoring matters too, and is easy to miss: control returns to the servlet afterwards and
the response path still evaluates authorization.

### M32 — the subscription graph is no longer re-read per event

`activeMatching` called `all()`, which was a `conn.fetch(SUB_GRAPH)` — a full materialisation and
re-parse of the whole subscription graph, in its own transaction, on the writer's request thread, on
**every** resource change. `all()` is now an invalidated in-memory snapshot: a version counter read
before the load, so a write landing mid-load is not lost.

*(Deviation from the suggested fix, which was a topic-filtered SELECT plus a cache. The SELECT is not
worth writing: a container topic matches by IRI prefix, so the filter is `STRSTARTS` over a set that
is now already in memory, and scanning a few hundred records costs nothing next to the transaction
the cache removes — while putting the prefix rule in a query string as well as in
`Subscription.covers` gives the two somewhere to disagree about what a topic covers. The companion
suggestion to hand listeners the event **list** was also dropped: it existed to amortise the
per-event `all()`, which is now O(1).)* `DispatcherAndCacheTest` measures this with a counting store
rather than asserting it: fifty matches after priming perform **zero** further reads.

### M33 / M34 — a delivery pool that a subscriber cannot hold open

Bounded in three directions — workers (`lws.webhook.threads`), queue depth
(`lws.webhook.queue-capacity`) and per-host in-flight deliveries
(`lws.webhook.max-in-flight-per-host`) — with work refused by any bound dropped and logged rather
than queued. Back-off is now scheduled onto a separate single-thread scheduler and re-submitted,
instead of `Thread.sleep` on the worker: one item could previously own a thread for the whole of
`max-attempts × backoff`, about 95 seconds on the shipped defaults, doing nothing.

Retries are classified by the new `DeliveryOutcome`: 2xx delivered; 5xx/429/transient I/O retried;
**410 Gone deactivates the subscription at once** rather than after ten consecutive failures; any
other 4xx, and an inbox this client cannot even build a request for (a `mailto:` that `URI.create`
accepts and `HttpRequest.newBuilder` throws on), counted as a failure and never retried. Three
regression tests drive a real local inbox and count the attempts: a 404 is asked once, a 503 is asked
`max-attempts` times, a 410 is asked once and deactivates.

### M35 — every delivery was being rejected as forged

`@authority` came from `URI.getPort()`, which returns the port as *written*, so an inbox recorded as
`https://host:443/hook` was signed over `host:443` while the wire `Host` carries `host`. RFC 3986
§6.2.3 makes a scheme's default port equivalent to no port, so a conformant verifier rebuilt a
different base and rejected **every** delivery to that inbox. Nothing on this side noticed: the
rejection arrived as a 4xx, was retried, and eventually deactivated the subscription — a correct
subscriber presenting as a broken one. The existing `WebhookDeliveryTest` could not catch it because
it rebuilds the base the same way *and* uses a non-default port, so the bug is invisible from there;
the new `WebhookSigningAndKeysTest` verifies against a base it builds itself, and covers `:443`,
`:80`, a non-default port and a mixed-case host.

### M36 — the seed that signs everything

Written owner-only into a temp file and moved into place with `ATOMIC_MOVE`; the move deliberately
does not replace, so a process that lost the race re-reads the winner's key rather than overwriting
the one subscribers are already verifying against. Owner-only is POSIX permissions where they exist
and the `java.io.File` calls (Windows ACLs) otherwise, and a filesystem that can express neither
earns a warning rather than a refusal to start.

The read is now checked. A malformed file reached `Base64.getUrlDecoder()`, which raises
`IllegalArgumentException` — not an `IOException`, so it went straight past the constructor's catch —
and a short seed reached BouncyCastle, which answered `ArrayIndexOutOfBoundsException: arraycopy`.
**Measured**: a 16-byte seed produced exactly that. Both now name the file and say what to do.

### L39 — the subscription collection was readable by anyone

`listCollection` was an unguarded `listFor(webId)`, and `listFor(null)` matches every subscription
whose `subscriberWebId` is null — so any unauthenticated request enumerated every
anonymously-created subscription, inbox URLs and topics included. Now authentication is required and
a caller sees its own; a storage controller sees all. The decision went into
`SubscriptionService.listVisibleTo` rather than the servlet, for the reason `requireManage` moved
there in Batch H7 and the conditional-write rule moved in M20: it is the object every entry point
goes through.

**Note for operators.** Three new keys (`lws.webhook.threads`, `lws.webhook.queue-capacity`,
`lws.webhook.max-in-flight-per-host`), all mirrored in `lws.example.properties`. Two behaviour
changes worth knowing: a `410 Gone` from an inbox now deactivates the subscription immediately, and
`GET /.lws/subscriptions` now requires authentication. Existing subscriptions whose inbox was written
with an explicit `:443` should start verifying for the first time.

**A process note.** During this batch's reconnaissance a subagent, told explicitly and repeatedly not
to modify anything, replaced `WacAclService.onDelete` with a throwing mutation probe — reverting H24
in a way that would have aborted every delete in WAC mode. The full suite had passed *before* the
injection, so only the file-hash comparison caught it. That is the second such incident; the
practice that works is: read-only instruction in the prompt, and a hash check afterwards regardless.

---

# Fixed: the whole of P2 — Batches K through N (2026-08-27)

The performance, conformance and operability band. Every open item in it is closed:
**M4, M5, M6, M7, M8, M15, M16, M21, M22, M23, M26, M27, M28, M39, H20, L28**, the Conformance
bundle, and the prior-review findings **12**, **13** and **14**.

`mvn -o clean test` → **362 tests, 0 failures** (313 at the start of the band). `mvn -B verify`
passes the dependency-convergence enforcer.

## What the code disagreed with

Four of the suggestions in this document were wrong, incomplete, or already done. Each is recorded
with its evidence, because the next reader will otherwise re-derive them.

**M6's suggested fix does not fix M6.** "Move `recordJti` after the `ath` check" — but `ath` is
`sha256(accessToken)` where `accessToken` is the string the caller itself put in
`Authorization: DPoP <value>` (`AuthenticationFilter.java:122`). It is a consistency check between
two attacker-supplied strings, not evidence of holding anything: an unauthenticated client sends
`Authorization: DPoP garbage` with a self-signed proof carrying `ath = sha256("garbage")` and fills
the cache at exactly the same rate. The only checks a caller cannot satisfy alone are
`validator.validate(accessToken)` and `isBoundTo`, and both live in the filter, *after* `verifyProof`
returns. So the record moved out of `verifyProof` entirely, into a new `DpopValidator.claimProof`
called last. It stays one atomic `putIfAbsent`, and every check now in front of it is a pure function
of (request, proof, token), so moving it later opens no window: the same triple gets the same answer
whenever it is asked.

**M6 has a second defect in the same lines, not in the finding.** The cache expired an entry after
`maxAgeMs`, while a proof is accepted whenever its `iat` lies in `[now - maxAgeMs, now + skewMs]` —
a window `maxAgeMs + skewMs` wide. A proof minted up to `skewMs` in the future therefore outlived its
own replay record and was usable again for that last `skewMs`. The TTL is now the full acceptance
window.

**M4's timeout half was already done** (Batch D). What was not: a negative cache, and — a new finding
— **neither outbound leg refused redirects.** `javap` on nimbus-jose-jwt 10.0.2 shows
`DefaultResourceRetriever.openHTTPConnection` is a bare `URL.openConnection()`, and
`HttpURLConnection` follows 3xx by default; `OIDCProviderMetadata.resolve` followed them through the
SDK's default request. The outbound-fetch policy is applied to `iss` and again to the `jwks_uri` it
advertises, but a policy check only covers the address it is given — so a public, policy-approved
`jwks_uri` could `302` the server to `169.254.169.254` and the response would be read. That is
exactly the hole H5 closed for `HttpDocumentLoader` and H4 for the subject document, on the one path
neither covered. Both legs now refuse redirects outright (an OpenID provider publishes its discovery
document and JWKS at addresses it controls; a redirect there is not a case worth supporting), and the
JWKS fetch is size-capped as well.

**M23's third clause was already done by H15.** "Derive the container validator from cheap metadata
rather than hashing the full membership" — the served tag has been the persisted registry one since
H15, refreshed by `touch`. Nothing was hashing the membership.

## Note for operators

Six changes are deliberately breaking.

- **`lws.sparql.mode=REMOTE` will not start** without `lws.sparql.remote.accept-no-transactions=true`,
  and then requires all three of `lws.sparql.query` / `.update` / `.gsp`.
- **A grant naming only the ODRL action `modify` no longer authorizes `DELETE`**, and one naming only
  `delete` no longer authorizes a rewrite. Grants that relied on the two being the same must list
  both actions. This is M8, and the direction that matters is that a grant issued so somebody could
  edit one document authorized deleting it — and, on a container, `Depth: infinity`.
- **`PATCH` of an existing resource now requires `If-Match`** (428 without one), as `PUT` has since
  M20. `DELETE` deliberately does not.
- **`PUT` of an existing `.acl` now requires `If-Match`** too, and an ACL carries an `ETag`.
- **`GET /.lws/type-search` requires at least one `type` clause** (400 without one). It used to
  enumerate every resource the caller could read.
- **`POST` to a data resource is `405`**, not `409`.

And two directories are now locked down at startup: `<data-dir>/keys` and `lws.tls.dir` are created
owner-only, and an existing one is *tightened*. Point `lws.tls.dir` somewhere private if you had it
sharing a directory with anything another account needs to read.

New configuration keys, all mirrored in `lws.example.properties`, all secure-by-default:
`lws.sparql.remote.accept-no-transactions` (false), `lws.dpop.jti-cache-size` (100000),
`lws.ssi-cid.document-cache-seconds` (300), `lws.ssi-cid.document-failure-cache-seconds` (30),
`lws.hsts.max-age-seconds` (31536000), `lws.cors.allowed-origins` (empty — CORS off),
`lws.cors.max-age-seconds` (600).

## M26 — the previous helper could not restrict anything on Windows

`WebhookKeys.restrictToOwner` had a two-tier ladder: POSIX permissions, else the `java.io.File`
calls. The second tier does not work. `File.setReadable(false, false)` means "take read away from
everybody but the owner", `WinNTFileSystem` cannot express it, and the method is documented to return
`false` when the platform cannot — so on NTFS the conjunction was always false, the inherited ACL
granting `Users` stayed exactly where it was, and the server logged "Could not restrict … to
owner-only" at every startup. The webhook signing seed, whose whole point is that anyone who reads it
can forge RFC 9421 signatures against this storage's published JWKS, was never protected on the
platform this project is developed on.

`core/SecureFiles` replaces it with three tiers: POSIX mode **as a creation attribute** (so the file
is never briefly world-readable), else a **replacement Windows ACL** — a single ALLOW entry for the
file's owner via `AclFileAttributeView`, which drops inheritance along with every other principal and
is the real equivalent of `0600` — else a warning, once per path. The write itself goes to a temp
file restricted before anything is written into it and is moved into place atomically, so a kill in
the middle leaves the old file or no file, never half a key. `AcmeCertificateManager`'s ACME account
key and TLS domain key go through the same helper, as does the `tls/` directory (M26's third half,
which was created 0755).

## M16 — REMOTE is not a weaker isolation level, it is the absence of one

`RdfStore`'s javadoc said remote SPARQL backends "autocommit each operation", which reads like a
trade-off. It is not: a `write` callback that issues five requests is five independent operations
that another client can interleave with and that no failure rolls back. Enumerated against the code,
what REMOTE silently drops is every guarantee this server has spent three batches establishing — the
`If-Match` compare-and-swap inside the write (H23), ACL and linkset erasure committing with the
delete (H24), blob keys retired only once the metadata naming them commits (H13/H14), the linkset
read-modify-write (M18), and quota enforcement. `ResourceRegistry.put` alone is a `DELETE WHERE`
followed by a Graph Store `POST`, so a concurrent reader between the halves sees a spurious 404.

The alternative the finding offers — make each logical mutation one `DELETE…INSERT…WHERE` — cannot
reach most of that: the blob store is a filesystem and takes no part in any SPARQL request, and ACL
graph deletion is a separate Graph Store call however the registry write is expressed. So the mode is
refused unless asked for, and the javadoc says which guarantees it costs rather than implying it
costs none.

## M6 / M4 / M5 — what caching buys, and what it costs

Each of these three adds a cache in front of an outbound request an *unauthenticated* caller can
aim, and each pays for it in staleness. Stated plainly because none of it is free:

- **SSI-CID subject documents** (M5) are reused for `lws.ssi-cid.document-cache-seconds` (300), which
  is the window in which a **rotated or revoked verification key stays honoured**. Shorter than the
  JWKS cache's hour for exactly that reason. Bounded by total characters rather than entry count,
  because the entries are documents.
- **OIDC discovery failures** (M4) are remembered for a minute, keyed by the `iss` an unverified token
  supplied. An attacker who can make a real issuer's discovery fail — by making this server hammer it
  into a 429, say — gets a one-minute authentication outage for that issuer. The trade is accepted
  because a failing issuer is unusable for that period regardless, and the alternative is one outbound
  request per presentation, which is the finding.
- **The DPoP replay cache** (M6) is bounded, and an entry evicted for **size** has not expired: the
  proof that wrote it is replayable again from that moment. That is a fail-open, chosen deliberately
  — the alternative is refusing requests when the cache saturates, which converts a degraded guard
  into a self-inflicted outage — and it is counted and warned about rather than left silent. Size it
  with `lws.dpop.jti-cache-size`.

**M6 is narrowed, not closed.** Consuming the `jti` only after a valid, bound access token means an
*unauthenticated* caller can no longer fill the cache. It does not mean nobody can: `did:key`
credentials are self-issued and free to mint offline, so a party willing to hold one still can, at
the cost of a full request each. That is the same unauthenticated-credential-minting problem M9 and
H22 are about, and it is not fixable here.

## M21 — an entity-tag names a representation, and a write names a state

RFC 9110 §8.8.1 asks for a different entity-tag per representation. One RDF resource is served as
Turtle, JSON-LD, N-Triples, RDF/XML or TriG from one stored graph, and all five shared the stored
tag — so a client that had cached the Turtle and asked for JSON-LD was told `304 Not Modified`, of
the Turtle, and went on using it. Separately, `Vary: Accept` was set two lines *below* the `304`
return, so the one response a cache stores against a key never carried it (§15.4.5).

The difficulty is the interaction with `If-Match`, and it is the whole design. A read hands out
`<state>.ttl`; a write is conditioned on the resource's state, which is the `<state>` the registry
holds. Mixing the media type into a *hash* would have made the two unrelatable and broken every
conditional write. So the variant is **appended**, `IfMatch.namesState` strips a **known** variant
token (`RdfFormats.isVariantToken` is the authority, so a client-invented tag containing a dot cannot
be trimmed into matching), and `IfMatch.matches` stays exact — which is what keeps a cached Turtle
from being revalidated against JSON-LD.

Two deliberate choices inside that:

- **A write response carries the unqualified state tag.** A `201`/`204` has no body, so there is no
  representation to revalidate; the tag it returns is the concurrency token, and `namesState` accepts
  it as readily as any representation's.
- **A container page's number goes in the hashed half, not the variant half.** A client that read
  page 2 has not read the state a write would replace, so a page tag must not satisfy an `If-Match`
  on the container.

## M22 / Conformance — one document, two renderings

The storage-description tag was `Etags.forModel` over a model whose service and capability nodes are
*blank*. `forModel` sorts N-Triples lines, which makes it order-independent but not
blank-node-independent — Jena mints a fresh label per model instance — so identical content hashed
differently on every call (measured: `40ec162e5e06c3d7` against `d699cc4ca046b387`). A conditional
GET on discovery could never return `304`: every polling client re-transferred, and a shared cache
accumulated an entry per request.

Fixing that and the "the two renderings are not the same graph" conformance finding is one change,
and had to be: a tag computed from the JSON is only a valid validator for the RDF rendering if the
RDF rendering is derived from the same document. `buildDocument()` now builds one `JsonObject`;
`buildJson()` serializes it and `buildModel()` walks it. That is not an invention — an
`application/lws+json` document *is* JSON-LD carrying the LWS context, so its RDF interpretation maps
unprefixed terms into the LWS namespace, which is what the walker does. `conformsTo` is special-cased
to Dublin Core, and `serviceEndpoint` stays an `xsd:anyURI` literal per the vocabulary's stated range.

What the RDF rendering had been dropping, silently: the `PatchSupport` media-type map, the
negotiable serializations and the digest algorithms — every capability was emitted as a blank node
carrying only its `rdf:type`. A client that negotiated Turtle was told materially less than one that
took the default, by the endpoint whose entire purpose is telling clients what the server can do.

`Etags.forModel` now says in its javadoc that it is only meaningful for a ground graph.

## Conformance — `Link: rel="type"` is a type source, bounded by a namespace

The searchindex spec's preferred way of declaring what a resource is was closed off twice over:
`HttpSupport.parseLinks` dropped every `rel="type"`, and `LinksetService` refused the `type` relation
outright. A client had no way to say its document is about a `schema:Person`, and a **binary**
resource — which has no content graph to assert one in — had no way to carry a type by any route.

`type` is now *server-augmented* rather than server-managed: the structural type the server assigns
is always emitted and always first, and a client may add to it. What it may add is bounded by
`LinksetService.declarableType`, which refuses **the whole `LWS.NS` namespace** and the LDP
interaction models.

The namespace refusal rather than a list is the point. A list would have to contain `lws:Container`
and `lws:DataResource` — and `lws:Storage`, `lws:StorageDescription`, `lws:AccessGrant`,
`lws:TypeIndexService`, and whatever is minted next. A denylist over a namespace somebody else
extends goes stale; refusing the namespace does not. Every path in — a linkset `PUT`, merge patch,
JSON patch, `Prefer: set-linkset`, and the new `applyDeclaredTypes` on `PUT`/`POST` — routes through
one `sanitizeUserRelations`, so there is one place to be right.

`applyDeclaredTypes` deliberately does **not** require `Prefer: set-linkset`. That preference is how
a client replaces its whole metadata document from headers; demanding it would mean a conformant
`Link: rel="type"` was ignored unless the client also asked for something else.

`parseTypeHint` still consumes the interaction models, so `Link: <lws#Container>` on a slash-less
name is still the contradiction M13 refuses — opening the relation did not quietly turn that into an
ordinary declared type.

## L28 — only `*` relaxes the rule

`If-None-Match` was never evaluated on a write, so create-only `PUT` could not be expressed: a client
that sent `If-None-Match: *` had it ignored and replaced whatever was there.

The trap in fixing it, and the reason the condition is `isStar()` rather than `isPresent()`: a
create-only `PUT` is a conditional request, so it must not be answered `428` for want of an
`If-Match` naming a version the client is asserting does not exist. But admitting *any* present
`If-None-Match` would mean `If-None-Match: "anything"` — a header naming no version of this resource
— stands in for the precondition, and one junk header turns every conditional write back into an
unconditional one. That is the lost update H23 and M20 closed, re-opened by the fix for L28.

`PATCH` is now conditional like `PUT` (prior-14). Placed **after** the method-applicability checks,
because `requirePrecondition` runs before `requireMergePatchable`: a `428` in front of it would have
turned a merge-patch on a PNG from `415` into "you needed a precondition", which is not true — it
could never have worked. `DELETE` stays unconditional: it is not an update, does not depend on having
read a version, and there is no lost state after a delete.

**The ACL's tag is stored, not derived** (prior-13). Hashing the ACL cannot work for the same reason
it could not work for the storage description: every authorization in an ACL is a blank node, so
`Etags.forModel` would change on every read, and a validator that changes on every read cannot
support a conditional write at all. A tag is minted per write into `urn:x-lws:acl-meta`, maintained
by `putSystemAclFor`, `deleteSystemAclFor` and `onDelete` — the last so a tag never outlives the
graph it describes and gets handed to a resource re-created at the same path, which is H24 one
indirection over. An ACL written before this existed carries no tag and is not asked for a
precondition, the same `etag() != null` guard resource `PUT` uses.

The console sends the tag too. A rule only the HTTP API enforces is not a rule — that is M20's
lesson, and two console users silently overwriting each other's ACL edits is the same failure with
worse consequences, because a lost update on an ACL *grants* access nobody chose.

## M7 — CORS, and the one combination that is refused

The server sent no `Access-Control-*` header anywhere. Because an `Authorization` header makes every
authenticated request non-simple, a browser sends a preflight `OPTIONS` first — carrying no
credentials — which the resource servlet answered `401` for any target the anonymous caller could not
read. So no browser application on another origin could complete a single request, and `acl:origin`,
which this server's WAC engine implements, was unreachable because no cross-origin request ever got
that far.

Decisions worth recording:

- **`Access-Control-Allow-Credentials` is never sent.** The API authenticates with a bearer or DPoP
  token in a header, which a cross-origin script must supply for itself. Never sending it means an
  allowed origin can only reach the storage with a token it already holds, and the console's session
  cookie cannot be borrowed. `/app` and `/callback` are excluded outright as well.
- **The preflight answer is a fixed method and header set.** One derived from the target would be the
  existence oracle `handleOptions` was rewritten to close, reachable without credentials.
- **`Vary: Origin` goes on every response the filter touches, including refusals** — otherwise a
  shared cache could serve an allowed origin's headers to a refused one.
- **`*` is refused at startup in open mode.** This is the fail-open the design would otherwise have
  had, and it is the shape a browser-app developer reaches for first:
  `lws.base-uri=http://localhost:8080`, `lws.dev.open=true` to skip configuring an owner, and `*` to
  make the app work. In open mode `DefaultAccessPolicy` permits every read *and every write*
  anonymously, so the authority is ambient and "we never send Allow-Credentials" protects nothing —
  there is no credential an attacking page would need. `*` would hand the whole storage to any
  website the developer visits. Refused, following the `lws.dev.open` + `lws.require-https`
  precedent; `lws.public-read=true` gets a warning, being the weaker, deliberate version of the same
  thing.

The allowed request-header list is derived from what the server actually reads (a `getHeader` sweep
over `http/` and `auth/`), and the exposed response-header list from what it sets — `ETag` because a
conditional write depends on it, `Location` because a `POST`'s result does, `WWW-Authenticate` and
`DPoP-Nonce` because RFC 9449 §8's nonce challenge is unusable from a browser without them.

`FusekiSparqlServer` gained an explicit `.enableCors(false)`. It is off by default today, so this is
a pin against a Jena default changing: Fuseki's own CORS defaults are `*` with every method and an
allow-listed `Authorization` header, on an endpoint that bypasses WAC and exposes the internal admin,
ACL and grant graphs.

## M23 / M39 — what a listing costs, and what it cannot stop costing

Reading a container opened one transaction for the membership and **one more per member**, because
the authorization filter ran outside the read and every `Authorizer.allows` opened its own — a
connection, a registry `CONSTRUCT` and a commit under owner mode; an ACL resolution per ancestor level
under WAC. A thousand-member container was a thousand transactions, roughly six thousand at WAC depth
five, serialized on the request thread. Page 1 cost the same as page 200, and a `304` cost it too.

Four changes, in decreasing order of what they buy:

1. **`Authorizer.allowsEverything`.** Where the answer cannot vary by resource — open mode, a WebID in
   `lws.owners`, public-read for reads — the per-member loop is skipped entirely. That is the
   ordinary deployment, and it turns O(members) into O(1). `DefaultAccessPolicy.permitsEveryResource`
   deliberately does **not** count a resource's own recorded `owner`: that disjunct is per-resource,
   and claiming it uniform would disclose one agent's members to another. `WacAclService` answers
   false, which is what per-resource access control costs.
2. **The filter moved inside the read transaction**, over cheap `ChildRef`s rather than full
   `ChildDesc`s. This is also *stronger* consistency than before: the listing is one snapshot, where
   it used to be one for the membership and a separate one per authorization decision.
3. **Page-sized metadata.** `ResourceRegistry.describe` fetches media type, size and modified for the
   members of one page. It keeps the containment constraint, so it is "describe these members", not
   "describe any IRI you name".
4. **The container RDF model is built only when RDF is negotiated.** Every container GET used to build
   it, including the overwhelming majority that serve `application/lws+json` and throw it away.

**Deviation.** The finding asks for the filter itself to be pushed into the page window. It cannot be:
`totalItems` reflects the disclosable view, which lws10-core requires and which this server has
implemented since before the review, and an exact count of what *this* client may see needs every
member considered. Paging over the raw membership instead would leak the container's true size, which
is a worse trade than the one being made. So the remaining O(members) is one in-transaction
authorization per member under WAC, and nothing at all under owner mode.

The same shortcut was applied to `SearchIndexService.typeIndex` and `typeSearch`, which had the
identical shape on endpoints cheaper to reach than a large container GET.

## prior-12 — an index that can only ever deny

Every grant check pulled every stored grant document across the wire and parsed each one, so a
storage holding grants for ten thousand agents did ten thousand JSON parses to answer a question
about one of them.

Each grant now also stores its policies' assignees as `urn:x-lws:accessAssignee` triples, and
`storedGrants(principal)` filters on them. **The JSON stays authoritative** — `assigneeMatches` still
reads the assignee out of the document — so the index is a pre-filter that can only remove candidates
from consideration. An index that disagreed with the document it indexes cannot grant access; the
worst it can do is fail to consider a grant, which denies. That is the right direction for a
denormalisation to fail in, and it is why this was worth doing at all.

Legacy grants have no index triples, and the query's `OPTIONAL` + `FILTER(!BOUND(?assignee) || …)`
admits them unconditionally, so a grant written by an earlier version goes on being evaluated exactly
as it was rather than silently ceasing to apply. `indexLegacyGrants()` backfills at construction so
the benefit is not confined to grants written from here on; a failure there is logged and costs only
the narrowing.

Parsed documents are cached keyed by their own text, so there is no invalidation to get wrong: a
changed grant is a different string and simply misses.

**Deviation.** No target-prefix index. `targetCovers` is a prefix match, which SPARQL expresses badly,
and the assignee filter already bounds the candidate set to "grants that could name me" — which is
the bound the finding is about.

## H20 — nothing read the Subject, and the Subject cost a session

Apache Shiro is gone from the source. `AuthenticationFilter` built a `Subject` and called `login()`
per authenticated request; `DefaultSubjectDAO` therefore created a native session with a 30-minute
timeout in an in-memory DAO, and nothing ever logged out. Nothing read it back — there is no
`SecurityUtils.getSubject()`, `hasRole` or `isPermitted` anywhere, because authorization is decided
by `core.Authorizer` from the resource IRI and mode — and `did:key` credentials are self-issued, so
anyone could mint an unlimited stream of valid ones offline and pin hundreds of thousands of session
objects without a single request having to succeed.

`ShiroSupport`, `LwsRealm` and `LwsAuthenticationToken` are deleted. The one thing the realm did
that mattered — refusing a token whose subject was absent — is kept as an explicit guard in the
filter, because a future validator that produced such a principal would otherwise authenticate a
request as nobody, and every owner and ACL comparison downstream is against a WebID.

The dependency could not simply be dropped: `jena-fuseki-main` declares `shiro-core` and
`shiro-web:jakarta` itself. It is now a `dependencyManagement` pin rather than a direct dependency,
and since Fuseki is `<optional>` here, a deployment that does not opt into the embedded SPARQL
endpoint gets no Shiro at all.

## The adversarial pass over P2, and what it found

Five read-only skeptics over the finished band, each finding paired with an independent verifier
told to *refute* it. Twenty-five claims: **17 confirmed, 5 refuted, 3 partial.** Thirteen produced
code changes. As in Batch H, the pass was worth more than several of the fixes it audited.

**The worst of it was pre-existing, and the fix walked past it.** `AuthenticationFilter` gated both
RFC 9449 §7.1 downgrade defences on `bearer &&` — but `LwsCredentialValidator` routes by the
credential's *shape*, parsing the value as a JWT first and reaching the SAML validator only when that
fails. So the word `SAML2` was an unconditional alias for `Bearer` for every JWT, with both defences
removed: a captured `cnf.jkt`-bound token was honoured with no proof, and `lws.dpop.require=true` was
bypassed by changing one word in the request. Not introduced by this band — but this band edited
those exact lines, wrote a "Fixed:" note claiming the guarantee, and did not look at the branch next
to the one it was standing on. Both guards now apply to every non-DPoP scheme, and announcing
`SAML2` while presenting a JWT is refused outright.

**Two defects the band introduced itself.**

*CORS `Vary` was erased by content negotiation.* The filter `add`s `Vary: Origin`; the servlets then
declared `Vary: Accept` with `setHeader`, which replaces. Every negotiated response said it varied
only by `Accept`, so a shared cache keyed on `Accept` could store one origin's
`Access-Control-Allow-Origin` and serve it to a request from another — defeating the header's whole
purpose on the responses that carry data. All six sites now go through `HttpSupport.vary`, which
appends and de-duplicates.

*Moving the listing filter into the read transaction silently broke Web Access Control.* A decision
made inside a unit of work resolves `acl:agentGroup` membership from cache alone —
`WacAclService` refuses to dereference a group document while one is open, which is H16 — and the
container's own warm-up does not cover its members: it resolves the container's `acl:accessTo`
authorizations, while members are governed by its `acl:default` ones or by ACLs of their own. A
member behind an uncached group would have vanished from `items` *and* from `totalItems`, with a
debug line as the only trace. It fails closed, so it was an under-reporting listing rather than a
disclosure, but it is exactly the sibling-path pattern: `delete` enumerates its subtree and then warms
each member, and `read` gained the in-transaction check without the matching warm-up. It has one now.

**The ACL surface, which L28 had just given an entity-tag, needed three more.** The tag and the body
were read in two separate transactions, so a write landing between them handed a client a body from
one version under a tag naming the next — and a write conditioned on that tag then passed a
precondition against a version it never saw, which is the lost update the tag exists to prevent. They
are one `readAcl` now. A `PUT` of an *empty* ACL minted a tag for it, and since `resolve` treats an
empty ACL graph as absent, `GET` answered `404` without ever disclosing the tag while `PUT` demanded
an `If-Match` naming it — an ACL address that could be neither read nor replaced. Storing an empty
ACL now erases the graph and the tag together. And `LegacyAclMigration`, which moves ACL graphs
directly, maintained neither: a migrated ACL had no tag (so it kept the pre-fix unconditional
behaviour for exactly the ACLs an operator inherited) and a deleted orphan left one behind (H24's
resurrection, one indirection over).

**Two configurations that produced the opposite of what they looked like.** `lws.tls.enabled` with
`lws.behind-proxy` means the server terminates TLS *and* trusts `X-Forwarded-Proto` from a proxy that
is not there — so any client could claim its plaintext request arrived over TLS and skip both the
HTTPS redirect and M28's 503 hold. Refused at startup. And an `https` base URI with neither setting
means nothing terminates TLS, so no request is ever `isSecure()`: no `Secure` on the session cookie
and no HSTS at all, from a configuration that reads like production. Warned about.

**The rest.** `AcmeCertificateManager` tightened the TLS directory only inside `acquire()`, which an
ordinary restart with a valid certificate never reaches — so the operator note promising a startup
tightening was false for the whole life of a certificate. The Windows ACL was built from the file's
*owner* rather than the running process, which on the path that exists to tighten a directory
somebody else created would have locked the server out of its own key store. `GrantAuthorizer.prepare`
— on the warm-up path every read, write and delete takes, once per descendant on a recursive delete —
transferred the complete JSON document of every grant in the storage to keep only the issuer column,
which is prior-12's cost on the one path prior-12's index does not narrow. A filtered linkset
(`Prefer: include`/`omit`) was served under the *full* document's entity-tag with no `Vary`, so a
client that revalidated without the preference was told `304` and kept the filtered document as
though it were the whole thing — M21's rule, on the one multi-representation resource M21 skipped.
The ACL `PUT` was the only body-reading write in the servlet that skipped the RFC 9530
`Content-Digest` check. And the console still gated every delete control on `canWrite` over the
*container*, which is the wrong resource and, since M8, the wrong mode.

**Refuted, and worth recording as refuted:** that `SecureFiles.writeOwnerOnly` silently writes a
secret it could not protect (it does, and that is the documented choice — a FAT volume cannot express
the permission and refusing to start would be worse); that the console's ACL delete is unconditional
(it is, and `deleteAclFor` treats an absent `If-Match` as no precondition, which is the same rule
resource `DELETE` follows); that the `webId == null` guard answers the wrong scheme.

**Two findings were about this document rather than the code.** The `lws.dpop.jti-cache-size` comment
said the acceptance window is five minutes when the replay window is six (`maxAgeMs + skewMs`), so
its sizing guidance was 20% low. And the README claimed `<optional>` on `jena-fuseki-main` keeps
Fuseki and Shiro out of the shipped jar; it does not — `<optional>` stops a *downstream consumer*
inheriting them, while `lws-server.jar` still contains both and the SPARQL endpoint is off by
configuration, not by absence.

**A process note.** The pass ran read-only under an explicit constraint naming the forbidden tools
*and* the forbidden shell verbs, with file hashes compared before and after. Nothing was mutated this
time — the first band where both the reconnaissance and the adversarial passes held.

## A process note

The reconnaissance and adversarial passes for this band ran as read-only subagents under an explicit
constraint naming the forbidden tools *and* the forbidden shell verbs, with a file-hash comparison
before and after. Both held this time. The reconnaissance pass earned its cost twice over: it is what
found the JWKS redirect hole and the DPoP TTL gap, neither of which is in this document, and it is
what refuted M6's suggested fix before it was written.

---

# Fixed: N3, N4, N5 (and a new N6) — Batch O (2026-08-27)

`mvn -o clean test` is green: **382 tests, 0 failures** (366 before this batch).

## N3 — a nested unit of work aborted its caller's transaction

**CONFIRMED by measurement, and worse than the finding described.** The finding said an exception
inside a nested inlined read could abort the outer write, after which `write()` might return normally
with half the work committed. Both halves are true, and the second is reachable today.

The probe, on `DatasetFactory.createTxnMem()` against the pre-fix `Tdb2RdfStore`: a write callback
that inserted a triple, swallowed an exception raised inside a `conn.querySelect` row handler, and
then inserted a second triple. Result — the ambient transaction was **closed**, the first triple was
**lost**, and the second **committed on its own**, outside any transaction, with the TDB2 writer lock
released mid-callback. Not a narrow race: a partially applied, non-atomic, unlocked write, which is
precisely the hazard `RdfStore`'s contract says the TDB2 backend does not have (M16). The swallow is
this codebase's own house style — `WacAclService.prepare` and `SearchIndexService.onResourceEvent`
both catch and log rather than fail a request over an advisory step.

**The obvious fix was written first and then rejected.** The finding located the defect at
`RdfStore.read`-inside-`RdfStore.write`, so the natural move is to join the ambient transaction in
`Tdb2RdfStore` instead of handing it to Jena's `Txn`. That leaves the mechanism fully live.
`RDFConnectionLocal` wraps **every** operation in its own `Txn` frame — `update`, `put`, `delete`,
`load` and `fetch` on the dataset; `querySelect`, `queryAsk`, `queryConstruct` on the connection —
and each of those frames has the same unguarded `onThrowable -> abort(); end();`. So the reachable
triggers were never only the eight `authorize` calls inside write lambdas: they include
`WacAclService`'s `row.getLiteral("e")` returning null for a non-literal binding,
`ResourceRegistry.children`'s `row.getResource("c").getURI()` on a blank node, and every other row
handler in the server.

**So the fix is one level down.** The outermost frame begins and resolves the transaction on the real
dataset; the callback is handed a connection over a `DatasetGraphWrapper` whose `begin`/`commit`/
`abort`/`end`/`close` are **inert**. `isInTransaction`, `transactionMode`, `transactionType` and
`promote` still delegate, so Jena's own compatibility checks behave exactly as before: inner frames
still see an open transaction, join it, read their own uncommitted writes, and skip the commit. What
they can no longer do is resolve a transaction they did not begin.

Verified on all five semantics before it was written, and pinned by `NestedUnitOfWorkTest`:
read-your-own-write inside a transaction; a propagating throw aborts everything and leaves the
dataset clean; a nested read sees the outer uncommitted write; a swallowed nested failure leaves the
outer transaction open; `conn.put`/`conn.fetch` still reach the real dataset.

**Operator-visible:** a failure raised inside a nested read used to surface with a suppressed
`TransactionException: Not in a transaction`. That was never a real failure, only this bug's
fingerprint, and it is now gone from logs and from problem+json cause chains.

## N4 — a malformed ACL denies; it does not throw

Three sites, not the one recorded.

1. `matches` tested `isResource()`, true for a blank node, then passed `asResource().getURI()` —
   `null` — into the group cache. Now `isURIResource()`, and the authorization is skipped.
2. **Unrecorded second site:** `groupMembers` collected members with the same test, and `Set.copyOf`
   rejects nulls outright, so one `vcard:hasMember [ ]` threw out of the middle of the decision. This
   is worse than a self-inflicted 500: a local group document is an ordinary resource, so an agent
   with Write on it could 500 every request governed by *someone else's* ACL that names it — and it
   denied the members who genuinely were in the group, so it was a full denial as well.
3. `groupMembers`' local branch used a bare `conn.fetch`. TDB2 answers an absent graph with an empty
   model, but a remote Graph Store Protocol backend answers `404`, and an unabsorbed `404` there is a
   `500` on every decision naming a local group with no document. It now uses the same `fetchOrEmpty`
   the ACL lookup uses.

`originAllowed` and `SubscriptionService.fromModel` moved to `isURIResource()` as well. Neither is
reachable today — both read server-written graphs — and the point is that no
`isResource()`-then-`getURI()` pair is left in the tree to be copied from. That sweep is complete:
those four were the only such pairs in `src/main/java`.

**Two L-band items in the same file were deliberately NOT taken.** Both look cheap and are not:

- *Requiring `rdf:type acl:Authorization`.* The finding is real — any subject carrying `acl:accessTo`
  and `acl:mode` authorizes today. But a resource's own ACL outranks container inheritance, so an
  untyped own-ACL would suddenly grant **nothing**, including `acl:Control` — and `requireControl`
  would then refuse every principal, the configured owner included, for that resource and, if it is a
  container's, its whole subtree. `LegacyAclMigration` moves operator-written graphs verbatim, so an
  upgrade can create exactly that, with no HTTP recovery path. Landing this needs a startup sweep over
  every ACL graph plus a migration-time repair, not just the type test. Left open with that as its
  design.
- *Dropping the cache for local group documents so revocation is immediate.* `allows` iterates every
  authorization and `matches` every `acl:agentGroup` without short-circuiting, and whoever holds
  `acl:Control` over a resource writes that ACL. The cache's `maximumSize(1_000)` and TTL are the only
  damping there is; removing them for local groups means N distinct local reads per decision, per
  issuer, inside the writer lock. It would also make that read the hot path for exactly the nested
  read N3 is about. Left open until it can be charged to an explicit per-decision cap.

## N5 — a stored linkset could be grown past what any reader could parse

**CONFIRMED, by a different mechanism than the review recorded, with a second amplifier it missed.**

**What was measured on this classpath.** The JSON provider caps its own nesting at 1,000 and reports
that as a bare `java.lang.RuntimeException` — not `JsonException`, not `IllegalStateException` — so
every `catch (JsonException | IllegalStateException | StackOverflowError)` in the tree let it
through. On a 512 KiB servlet stack the reader throws `StackOverflowError` at about 999 instead,
which is an `Error` and escapes `catch (Exception)` as well. **The writer has no cap at all**: a tree
1,500 deep serializes happily into 9,010 bytes and can never be read back. That asymmetry is the
finding, and it makes the poisoning permanent.

There is also a **JVM-wide amplifier not in the original report**: a `StackOverflowError` raised while
the provider's message class is being initialised poisons that class for the life of the process,
after which every later parse error anywhere in the server surfaces as `NoClassDefFoundError` rather
than the exception its callers catch. One deep document degrades all JSON error handling
process-wide.

**Deviation from the suggested fix.** The suggestion was to call `JsonLimits.requireBoundedNesting` on
the merged result. That cannot be written: the only overload takes `byte[]`, obtaining bytes means
`toString()`, and the provider's generator is recursive — so producing something to check would blow
the stack on exactly the documents the check exists to refuse. A non-recursive walk over the parsed
value was written instead (`JsonLimits.requireBounded`), with an explicit stack of iterators, holding
at most one frame per open container.

**Extension beyond the suggestion.** A depth bound alone does not close the amplification. RFC 6902
`copy` from `""` duplicates the whole document into a new member: one level deeper, **twice the
size**. Sixty permitted doublings is heap exhaustion inside the single global writer lock. So the
guard bounds size as well, under a new key `lws.linkset.max-bytes` (default 1 MiB). The size
accumulator is a deliberate *lower* bound — commas and string escaping are not counted — so it can
never refuse a document that would in fact have fit, and it fails before the `toString()` that would
otherwise have to allocate the thing being measured.

**Off-by-two, caught while reviewing this batch's own design.** The bound is applied to the user
object at `MAX_NESTING_DEPTH - 2`, not `MAX_NESTING_DEPTH`, because `build()` wraps it in the linkset
array and its member object. At the full depth the server would render a document two levels past
what `parseObject` accepts on the way back in — it would hand out a linkset it then refused to be
given. `aLinksetTheServerRendersIsOneItWillAcceptBack` pins the round trip.

**The read side is a guard, not just a catch.** `readUserMetadata` and `typesOf` now run the byte scan
over the stored literal *before* parsing it, which is the idiom `JsonLimits` was written for, and
their catches were widened to `RuntimeException | StackOverflowError` so the provider's own cap no
longer escapes. Degrading to "no user-managed links" is what makes the repair path work: `update`
reads through `readUserMetadata` first, so without it a poisoned linkset could not even be overwritten
by a `PUT`. It is logged at WARN, because silently dropping stored metadata should not be something to
discover from a diff. `filterRelations`, which had no catch at all, got one; `AccessService.tryParse`
and `AccessServlet.assignees` were widened defensively (their stored documents are bounded at create,
so those only matter for records written by a build predating M17).

**`typesOf` mattered more than its size suggests.** It runs from `allDeclaredTypes` over *every*
stored linkset during the search-index build, so one poisoned resource failed the index for the whole
storage rather than only its own read.

**The blob patch paths were half of this too.** `patchJsonPatch` stored an unbounded result, so the
*next* patch of that resource was refused `400` with a message blaming a three-token patch for a
document the server itself had stored. The result is now bounded, and a stored document that cannot be
patched answers `409` naming the stored state — which `PUT` resolves — instead of `400` blaming the
client. `patchMerge` needs no result bound and deliberately has none: merge patch recurses along the
*patch*, so its result is never deeper than the deeper of its two already-bounded inputs. Only JSON
Patch, which addresses by pointer, can amplify.

## N6 (new) — a remotely fetched credential document was parsed with no depth bound

Found while sweeping the parse sites for N5. `SsiCidValidator` dereferences a URL the credential
itself names and parses the result with no guard, inside a `catch (Exception)` that does not catch
`Error`. The loader bounds the fetch's size (2 MiB) and its time, but not its *shape*, and `[`
repeated four thousand times is four kilobytes. An **unauthenticated** client chooses that URL — this
runs before any credential is verified. Guarded, and the catch widened.

## Note for operators

Three deliberately breaking changes:

1. A linkset `PUT`/`PATCH` whose user-managed part would serialize past `lws.linkset.max-bytes`
   (1 MiB) is refused `400`. The linkset is relation-to-link-target metadata; 1 MiB is thousands of
   targets. Configurable.
2. A linkset write whose **result** would nest past 62 levels is refused `400`. M17 measured what real
   documents cost — RFC 9264 link attributes are flat, and Jena's own JSON-LD projection is depth 3-4
   — so nothing legitimate is near it.
3. A JSON blob whose stored form is too deep to parse answers `409` on `PATCH` where it answered
   `400`, and names `PUT` as the way out.

Recovery for a linkset already poisoned: it is read as empty, logged at WARN, and a `PUT` replaces it.

## A note on the negative check

The convention here is to run each new regression test against the unfixed code and check that it
fails for the right reason. `StoredLinksetDepthTest`'s size test did not fail — it **hung the
server**, which is the denial of service the finding describes, and had to be killed. The two source
files were restored from a copy taken beforehand and verified by hash.

---

# Fixed: N1, N2 — Batch P (2026-08-27)

`mvn -o clean test` is green: **391 tests, 0 failures**.

## N1 — and the reason it was unreachable, which was a worse bug

The finding: an RDF write parses its body *inside* the write transaction, so for JSON-LD a remote
`@context` is a synchronous outbound GET under TDB2's single writer lock — H16's harm by a path H16
did not cover, reachable by any client the moment an operator sets
`lws.jsonld.allowed-context-hosts` to the value this project's own example file suggests.

**Measured first, and the measurement inverted the finding.** `RdfIO` installs the refuse-all default
from a static initializer, and a static initializer runs on first *use* of the class. In the
assembled server nothing touches `RdfIO` until `LwsComponents` has already called
`JsonLdSecurity.install(config.jsonLdAllowedContextHosts())` and gone on to ensure the storage root —
so the first RDF operation of the process **replaced the operator's allow-list with refuse-all**.
Verified directly: the installed options object had a different identity after one call to
`RdfIO.writeString`, and installing the allow-list *after* `RdfIO` was loaded produced a real
connection attempt where installing it before produced "not permitted".

So `lws.jsonld.allowed-context-hosts` was a documented configuration key that did nothing at all —
a control that does not do what it says, which this repo's own `SECURITY.md` puts in scope. No test
sets a non-empty allow-list, which is why nothing caught it.

Both halves had to land together: fixing the clobber is what makes N1 reachable.

1. `installDefault()` is now install-**if-absent**. An explicit `install` always wins, in either
   order, and cannot be silently downgraded by a class initializer that happens to run later.
2. `GuardedContextLoader` refuses to dereference anything while a store transaction is open on this
   thread, through a `BooleanSupplier` the wiring points at `RdfStore::inUnitOfWork`. This is
   `WacAclService`'s H16 rule applied verbatim to the one fetch it did not cover.

**Deviation from the suggested fix, and why.** `REVIEW.md` proposed a context cache warmed by a
throwaway pre-parse before the transaction. That was written and rejected. The warm-up would have to
run before `authorize` — the authoritative check is deliberately *inside* the transaction — so it
would hand an **anonymous** client the power to make the server issue blocking HTTPS GETs to paths of
its choosing on any allow-listed host, at ten seconds each, on a Jetty worker. That is a new
pre-authentication fetch primitive introduced by a fix for an availability bug, and no bound on the
cache makes it not one. Refusing under the lock needs no warm-up, no cache and no new key.

**The honest cost, recorded rather than papered over:** with the refusal in place a remote
`@context` cannot be resolved on the resource-write path at all, because that path always parses
inside the transaction. It still works everywhere that parses outside one — an ACL write, a fetched
WebID or group document, the console. The refusal says which case it is, so an operator can tell it
apart from the allow-list refusal. An inline `@context` object is unaffected, which is what storing
user data actually needs.

`Document.setDocumentUrl(url)` is also now set on a fetched context, so relative IRIs inside it
resolve against the document rather than against nothing.

## N2 — no blob I/O under the writer lock

Three sites, all inside `rdf.write`: `storeContent` streamed up to `lws.max-request-bytes` (64 MiB)
into the binary store, and `patchMerge`/`patchJsonPatch` additionally *read* the whole stored blob,
parsed it, applied the patch and wrote the result — all while every other write in the storage
waited, and on an NFS or SMB data directory that is network I/O under a global lock.

**`storeContent`.** The resolved type is a pure function of the request, so it is computed before
the transaction and the bytes are staged then. That is not only cheaper, it is what makes the
staging *safe without bookkeeping*: bytes are staged only when the request resolves to a non-RDF
resource, and in that case the transaction either uses them or throws (a type change is a 409, a
container body is refused), and `writeWithBlobs` sweeps `staged` on every throw. There is no branch
that commits while leaving a staged blob unreferenced, so no "unclaimed" set is needed — an earlier
draft had one, and it deleted live blobs on its own fallback path.

**The patch paths** hoist the read, the patch application and the write. That is a read-modify-write,
so the transaction has to re-check what the computation was based on or it reintroduces the lost
update Batch G closed. It compares **`binaryKey` identity**, not the entity-tag: every write mints a
fresh key, so an unchanged key is proof nothing intervened, whereas an entity-tag is a 64-bit prefix
of a content hash and `If-Match: *` is satisfied by *any* version at all — a client sending `*` would
have had no protection. A mismatch is `412`, which is exactly "the state you based this on is gone",
and a PATCH here already has to carry a precondition, so the client has the machinery to retry.

**An ordering regression, caught by the suite and worth recording.** The first cut hoisted the read
unconditionally, so a merge-patch of an *RDF* resource read a null blob and answered `409` where it
had answered `415`. The fix is that the hoist happens **only when the stored resource is already a
JSON non-RDF resource**; when it is not, nothing is staged and every refusal — `404`, the container
`409`, the authorization `401`/`403`, the precondition `412`, the media-type `415` — is still made
inside the transaction in the order it was made before. Hoisting the media-type check would have
reordered it ahead of the authorization check and told an unauthorized client the media type of a
resource it may not read, which is the very disclosure Batch Q closes.

---

# Fixed: the existence oracle — Batch Q (2026-08-27)

`mvn -o clean test` is green: **397 tests, 0 failures**.

This is the one code item TODO.md's long tail still listed, deferred once with the note that the
naive hoist does not work. It does not; this does something else.

**The leak.** Existence is resolved before authorization on every path, so a client who may not read
a resource was told `403` when it existed and `404` when it did not. Two further surfaces belong to
the same family and were closed with it: `allowedMethods` took no principal, so the `Allow` header on
OPTIONS, on a 405 and on a 409 disclosed the resource's *type*; and `SubscriptionService` answered
`201 Created` for a topic that does not exist while answering a refusal for a hidden one, which is a
sharper discriminator than any pair of status codes.

**The rule.** An authenticated principal without Read is answered `404` whether or not the resource
is there. Keyed on **Read**, not on the refused mode: a client who may read but not write already
knows the resource exists, and answering `404` to their `PUT` would be a lie that helps nobody.

**Anonymous still gets `401`,** deliberately. An unauthenticated client has to be told that
authenticating is what it is missing, or it can never discover how to sign in — RFC 9110's challenge
and the whole Solid discovery story depend on it.

**Two leaks the design missed, both found by the new test rather than by reading.**

1. *OPTIONS was inverted.* It refused a hidden resource and answered `204` with an `Allow` header for
   an absent path — so it discriminated in the opposite direction from everything else. It now
   answers a resource the caller may not read exactly as it answers one that is not there, and skips
   the `Accept-Post`/`Accept-Patch` description for the same reason. A `404` there and a `204` here
   would have been the same disclosure with the codes swapped.
2. *Anonymous kept the whole oracle.* Masking `403` covers only the case where authorization runs;
   an absent resource never reaches it, so anonymous got `401` for hidden and `404` for absent —
   the same disclosure, and the easier one to exploit because it needs no credential. Absence is now
   answered through the same helper.

**The predicate for absence is the subtle part, and the first version was wrong.** Asking
`authorizer.allows(principal, iri, READ)` about an absent IRI always answers false, because
`OwnerAuthorizer` denies any IRI with no registry entry — so it masked every `404` in the server,
open mode included, and turned nine passing assertions into `401`. That is precisely the trap H16
recorded when it rejected hoisting authorization above the existence check. Two questions *are*
meaningful about a resource that is not there: whether this principal may read everything
(`allowsEverything`, true in open mode, for a configured owner and on a public-read storage), and
whether they may read the container it would have been in. A client who can list the parent can
already see the child is not among its members, so telling them plainly costs nothing.

**Also closed:** the servlet's pre-body write filter had its own copy of the 401/403 decision and
answered `403` where the authoritative check a moment later would have masked it. It now goes through
the same helper. A control that two code paths implement differently is a control with a way around
it — the same lesson M20 and the `IfMatch` consolidation recorded.

**Cacheability.** OPTIONS (`204`) and the method-not-allowed response (`405`) are both heuristically
cacheable under RFC 9110 §15.1 and now vary by principal, so both are marked
`Cache-Control: private, no-store`. Without that a shared cache could serve one client's view of the
storage to another — a new leak manufactured by the fix for the old one.

## What this does NOT close, stated plainly

Under Web Access Control the anonymous `401`/`404` split still discriminates, and no status-code
masking can fix it. WAC resolves a decision from the target's own ACL graph and falls back to the
nearest ancestor's `acl:default`, so a path with its own ACL answers differently from one without —
and under WAC, having an own ACL is very nearly the same fact as existing. Closing that means
changing the authorization model, not the status code. What is closed: the oracle for every
authenticated client, in every mode; and for anonymous clients, everywhere the parent container is
not readable. In owner mode it is closed outright.

## Note for operators

`lws.mask-forbidden-as-not-found` (default `true`). Two visible changes:

1. An authenticated client without Read now sees `404` where it saw `403`. A client that
   distinguished "forbidden" from "missing" to decide whether to request access will need the
   access-grant endpoint instead, which is what it is for.
2. `Allow` on OPTIONS and on a 405 no longer describes a resource the caller may not read, and both
   responses are now `private, no-store`.

Setting it to `false` restores the old behaviour, along with the disclosure.

---

# Fixed: the P3 test band, and two bugs it found — Batch R (2026-08-27)

`mvn -o clean test` → **515 tests, 0 failures** (397 before this batch; 366 at the start of the day).

All seven open test-band items are done. Two measurements were taken first, because the work order
for two of them turned on facts nobody had checked:

- **Headers set before `sendError` survive it on this stack.** Every existing `Link`-on-401
  assertion in the suite comes from a servlet that uses `setStatus`, so the DPoP paths — which use
  `sendError` — were unpinned. Measured: `WWW-Authenticate` and `Link` are both present. Had they
  not been, a nonce challenge carrying no nonce would have been a finding in itself (RFC 9449 §8).
- **Fuseki's read-only refusal is not one status code.** Measured: `POST /lws/update` → **404**
  (Fuseki registers no update endpoint at all when read-only), `POST /lws` → **400**, and the
  graph-store paths → **405 "Read-only"**. `REVIEW.md` guessed 403/405; the code is the authority,
  and the class javadoc now records why, so nobody "fixes" the assertions back to `>= 400`.

## What each item pinned

**An HTTP-level DPoP class** (`DpopHttpIntegrationTest`, 17 tests). No test sent a `DPoP` or `SAML2`
`Authorization` header at all before this. It covers all six of `AuthenticationFilter`'s refusal
steps — every one produces a `401`, so each test asserts the **exact** `WWW-Authenticate` string,
which is the only thing that distinguishes them. It also pins the RFC 9449 §7.1 downgrade defence
over the wire for **both** schemes: a `cnf.jkt`-bound token presented as `Bearer` *and* presented as
`SAML2` are refused. That second case is the pre-existing critical the P2 adversarial pass found —
the guards had been gated on `bearer &&`, so `SAML2` was an unconditional bypass — and it had no
end-to-end test until now. `AuthTestSupport` gained one overload (a five-argument
`signEdDSAWithCnf` taking an audience) so the test could mint a bound token **without** switching
the audience defence off, which is what the obvious shortcut would have done.

**M47 — the conformance suite under a configured owner** (`OperationsConformanceOwnerTest`, 28
tests). `OperationsConformanceTest` and its 435 lines ran in open mode and sent no credential, so
none of it asserted an authorization outcome. It is now an abstract base with two thin subclasses —
open mode and owner mode — with the 28 test methods moved **verbatim**: not one assertion, status
code or message string changed, because the whole point is that the identical assertions hold under
a real owner. `@TestInstance(PER_CLASS)` with a non-static `@BeforeAll` is what makes the boot able
to call an overridable hook; the alternatives (`@Nested`, `@ParameterizedTest`, a static-hiding
subclass) each fail for a reason recorded in the work order. All 28 pass in both modes.

**M40 — the SAML validity window.** `SamlValidator.withinValidity` had **zero executed lines**:
every fixture in the file either omitted `saml:Conditions` or emitted one with no `NotBefore` /
`NotOnOrAfter`, so both branches short-circuited. Now covered, including the two skew-tolerance
cases that fail if anyone tidies the skew term away, and the fail-closed case where an unparseable
timestamp must not be read as "no bound". The `AudienceRestriction` half of the finding was
**already covered** by three existing tests — verified rather than duplicated.

**M41 — grants** (12 tests). `dateTime` expiry in both directions with in-window controls, the
unparseable-bound and unknown-operator arms (both must be inert, not permissive), a two-constraint
validity window, the `client` `eq` and `isAnyOf` forms, the anonymous case where `clientId` is null,
and the three `targetCovers` branches — a container grant covering its members, a grant *without* a
trailing slash **not** covering a subtree, and a container grant not leaking to a sibling with a
shared prefix. That last one is what makes `startsWith` on the slashed value safe, and nothing
pinned it.

**M44 — a foreign key that was never actually verified.** `rejectsTokenSignedByKeyNotInJwks` minted
with `keyID("foreign")`, so Nimbus's key selector found no candidate and rejected the token before
`RSASSAVerifier` ever ran: the test passed without exercising signature verification at all. It now
re-mints with the provider's own `kid` over a different key pair, so the rejection has to come from
the cryptography — and the old case is kept under a name that says what it really tests, because the
two look identical from outside and only one of them is about signatures.

**M45 — Fuseki.** `>= 400` could not tell "the endpoint refused the write" from "the URL was
mistyped", and nothing checked that the write had not landed. Both mechanisms now have their own
test with the measured status, each bracketed by an `ASK` probe over the default graph *and* every
named graph — the old count assertion looked only at named graphs, so it would not have noticed the
write even if it had succeeded. Plus a read-write companion (without which the negative test proves
nothing) and a loopback-binding test guarded by `Assumptions` for hosts with only `lo`.

**The four untested classes.** `FileSystemBinaryStore` (10), `RdfFormats` (20), `Tdb2RdfStore` (5),
`LoginPage` (12). Two are worth calling out:

- The binary store's path-escape test asserts that **all five** entry points refuse a key resolving
  outside the base, and is backed by a reflective check that there *are* only five — the five-way
  loop on its own would not have stopped a sixth entry point from being added without the guard.
- `LoginPage`'s sharpest test renders the dev-login form from a loopback address and then submits it
  from a non-loopback one. The production code says in a comment that whether a control is *shown*
  and whether it may *run* are different questions; nothing tested it.

## Two real bugs the tests found

`RdfFormats` had two of the still-open low findings, and the tests were written to assert the
**correct** behaviour rather than enshrine the defect. Both are now fixed:

1. **`matchQuality` took the maximum quality over every matching media range instead of the quality
   of the most specific one** (RFC 9110 §12.5.1). Two consequences, and the second is the serious
   one. A client sending `application/*;q=0.9, application/ld+json;q=0.1` was served JSON-LD — the
   one application type it least wanted. And a client sending `*/*;q=0.9, text/turtle;q=0` was served
   **Turtle**, because the wildcard's 0.9 outvoted the explicit zero: `q=0` is a *refusal* (§12.4.2),
   so the server was answering with the single representation the client had said it would not
   accept. Specificity now ranks as the grammar does, and quality only breaks ties within a rank.
2. **Two `toLowerCase()` calls used the default locale.** On a Turkish-locale JVM
   `"APPLICATION/N-TRIPLES"` folds to a dotless `ı` and matches nothing, so a supported request body
   answered `415` on one machine and `200` on another. `Locale.ROOT` — a media type is a protocol
   token, not display text.

## Notes from the work, worth keeping

- The seven items were written by seven agents owning **disjoint file sets**, forbidden from
  touching `src/main`, `pom.xml` or any `.md`, and forbidden from running `mvn` (several agents in
  one tree would race on `target/`). `src/main` was hashed before and after and the only differences
  were the six files this session had edited itself. That is the fourth band to hold; see the process
  note on Batch N.
- Three agents independently verified library behaviour by **disassembling the jars in `~/.m2`**
  rather than assuming: that `FusekiServer.Builder.loopback(true)` really binds the connector to
  localhost, that `SPARQL_Update` answers `204` rather than `200` for a non-form body, and that
  `WicketTester` installs `IFeedbackMessageFilter.NONE` (so session feedback survives the request
  under the tester, where it would not in production — an exact-string assertion would otherwise
  have been wrong for a reason nobody would have found).
- One work-order item was **wrong about a platform**: it listed `"..\\escape"` beside `"../escape"`
  as a path-escape case. On POSIX a backslash is an ordinary filename character, so that assertion
  would have gone red on Linux. It is now its own test, guarded by asking the *platform*
  (`Path.of("..\\escape").getNameCount() > 1`) rather than by testing the OS name.

---

# Fixed: the first of the low tail — Batch S (2026-08-27)

An inventory of the ~65 low findings and 19 nits was taken first, checking each against the current
code rather than against the review text: **47 were already closed** as a side effect of the H/M
work, 3 do not apply, and 63 were genuinely still open. These are the ones taken in this pass,
chosen for being security- or conformance-relevant and self-contained. The rest are listed in
`TODO.md` with the inventory.

**Outbound fetch (SSRF) — the ranges the JDK does not know about.** `isSiteLocalAddress` covers only
RFC 1918. It does not cover carrier-grade NAT (`100.64.0.0/10`), which is where a great many hosts'
actual neighbours live; nor the benchmark range; nor `192.0.0.0/24`, the IETF protocol block that
carries NAT64 and DS-Lite; nor the TEST-NET ranges; nor `240.0.0.0/4`. All are now refused.

More importantly, **an IPv4 address tunnelled inside an IPv6 one reached the same host by a name none
of the IPv6 predicates recognised**. Four encodings do it — IPv4-mapped (`::ffff:a.b.c.d`),
IPv4-compatible (`::a.b.c.d`), 6to4 (`2002:aabb:ccdd::/48`) and the NAT64 well-known prefix
(`64:ff9b::/96`) — so `http://[::ffff:169.254.169.254]/` walked straight past a guard whose entire
purpose is to refuse `http://169.254.169.254/`. The embedded address is now unwrapped and checked
against the IPv4 rules, and a 6to4 address wrapping a genuinely public address is still permitted:
the rule is "check what it tunnels", not "refuse the whole form".

**Base58 could not round-trip a leading zero.** `decode` dropped `BigInteger.toByteArray`'s sign
byte only when the array was longer than one byte — but for a value of *zero* the whole array is the
artefact, so decoding `"1"` produced **two** zero bytes rather than one. That is the exact input a
leading-zero-preserving encoding exists to carry, and `did:key` identifiers are Base58.

**A linkset's server-managed relations were matched case-sensitively.** RFC 8288 §3.3 compares
relation types case-insensitively, so `Anchor` is the same relation as `anchor`. Matching exactly let
a client store an `Anchor` of its own choosing, which the renderer then emitted alongside the
server's real one: a single document asserting two different subjects, with the client's copy
indistinguishable from the server's to any consumer that lower-cases relation names — as a
conforming one must.

**`Last-Modified` was not a valid IMF-fixdate.** `RFC_1123_DATE_TIME` does not zero-pad the day of
month, so the server emitted `Tue, 3 Jun 2008` where RFC 9110 §5.6.7's grammar demands
`Tue, 03 Jun 2008` — a validator a strict cache is entitled to ignore, on eleven days of every
month. Now an explicit pattern under `Locale.ROOT`, because the day and month names are protocol
tokens rather than display text.

**A `405` from the access endpoint carried no `Allow`.** RFC 9110 §15.5.6 makes it mandatory, and it
was the one status on that servlet that omitted it.

**The `401` challenge advertised only `Bearer`.** The README says a client discovers how to
authenticate from the challenge, and this server also accepts `DPoP` and — when trust anchors are
configured — `SAML2`. A client that could only do DPoP had no way to find that out. All three are now
offered (RFC 9110 §11.6.1 permits several challenges); the scheme-specific `401`s raised inside
`AuthenticationFilter` still name the single scheme the request actually used.

**The bare-Jetty launcher advertised its exact Jetty version** on every response while the Spring
path suppressed it. Not a vulnerability and not a control — a free hint about which advisories to
try first, and one place the two deployments disagreed about their own posture.

Two further low findings — content-negotiation specificity and locale-sensitive case folding in
`RdfFormats` — were fixed in Batch R, where the tests that found them live.

---

# The adversarial pass over Batches O–S, and what it found — Batch T (2026-08-27)

`mvn -o clean test` → **521 tests, 0 failures**.

Four read-only skeptics were run over the band, each told to refute rather than review, each free to
compile and run throwaway probes. Three returned **UNSOUND** and one SOUND-WITH-CORRECTIONS. Every
defect below was **measured**, not argued, and every one is now fixed. This is the fifth time the
pass has been worth more than the work it audited, and the first time most of what it found was
introduced *by* that work.

## Regressions this band introduced, and the fixes

**1. Every refused write leaked its bytes.** `stageBytes` wrote the blob but the key was registered
in `BlobChanges.staged` at the far end — inside the transaction, after `authorize`. So every refusal
in between left the bytes on disk with nothing referencing them and nothing to sweep them. Measured:
five conditional `PUT`s refused `412` — the *ordinary* failure mode, since a replace must carry a
precondition — grew the store by **10 MB**; a denied 4 MiB `POST` leaked 4 MiB.

Worse, the quota became **fail-open**: `enforceQuota` runs before the registration, so a `507`
deposited the very bytes it had just refused, and `registry.totalBytes` cannot see them. Measured
with a 100 KB quota: five refused 1 MiB `POST`s left **5 MB** on disk, 52× the configured limit.

Fixed: `stageBytes` registers the key the moment the bytes exist, and a new `stagedOrDiscarded`
wrapper sweeps them when the failure happens *before* the transaction is even entered — which
`writeWithBlobs` never covered.

**2. The hoist put a content-dependent computation ahead of the authorization check — a value
oracle.** Applying a patch to a stored document was moved outside the transaction (correctly, for
N2), but its *failures* were thrown there too. An RFC 6902 `test` operation is a value comparison, so
"did this patch apply" is a read primitive. Measured against an authorizer that denies everything:

```
test with the correct value   -> 404 Resource not found
test with a wrong value       -> 409 JSON Patch could not be applied: ... failed for path '/ssn'
```

Reachable over HTTP by any principal holding **Append on a container but not Write on the child** —
the ordinary WAC drop-box shape — because the pre-body write filter is deliberately permissive. Batch
Q had just closed this class of disclosure; the N2 hoist reopened it one method over, and with a
sharper primitive: arbitrary members of an unreadable document could be read out by bisection.

Fixed with a `Prepared` record that *carries* the failure instead of throwing it, and re-raises it
inside the transaction after `authorize`, in the position it always occupied.

**3. `Tdb2RdfStore` opened its transaction outside the `try`.** `dataset.begin(type)` and
`RDFConnection.connect(...)` both ran before the `try`, so anything thrown between them orphaned a
write transaction on a pooled request thread. Measured, on real TDB2, from exactly one orphan:

```
store.writeDo returned normally (no exception, nothing logged)
another thread can see the "committed" write = false   <-- silently lost
another thread's WRITE BLOCKED FOREVER                 <-- all writes stop
```

Permanent and silent, because `outermost` is then false forever on that worker: every later write
returns `2xx` and commits nothing, while the TDB2 writer lock is never released. Fixed by building
the connection first and putting the `begin` inside the `try`.

**4. Fixing `Last-Modified` broke `If-Modified-Since`.** One formatter served as both sender and
parser, so making the sender emit a correct IMF-fixdate made the *reader* reject every other form.
Measured: `Tue, 3 Jun 2008 …` — which is exactly what this server emitted until the sender was
fixed — became unparseable, and an unparseable `If-Modified-Since` is silently treated as absent, so
the answer is a full `200` where a `304` was due. RFC 9110 §5.6.7 requires a recipient to accept all
three historical forms. There are now two formatters: strict out, lenient in.

**5. A raced read became a `500` carrying the data directory's absolute path.** Reading the blob
outside the transaction means a concurrent write can retire the key first. Measured: `500 Could not
read content: C:\…\blobs\72\94\72940eab…`, sent verbatim to the client because the servlet renders an
`LwsException`'s message as-is. Now a `NoSuchFileException` is the `412` this race was always meant
to produce, and any other I/O failure keeps its `500` with the message logged rather than sent.

**6. `patchMerge` had no result size bound.** The N5 work bounded JSON Patch and argued merge patch
could not amplify — true of *depth*, false of *size*. Measured with a 200 KB request cap: twelve
merge patches grew a stored blob to **1.2 MB**, with no ceiling, and every later read loads the whole
thing into heap. Now bounded like its sibling.

**7. `Q=0` was ignored, which defeated Batch R's own headline fix by one character.** Accept
*parameter names* are case-insensitive (RFC 9110 §5.6.6) and only the media type was being folded.
Measured: `*/*;Q=0.9, text/turtle;Q=0` → **Turtle** — the section's own example of "the server
answering with the single representation the client had said it would not accept", still broken
after the fix that was written for it. `RdfFormatsTest` had only tested the lower-case spelling.

## Oracle surfaces Batch Q claimed and did not close

Five siblings, all measured, all now routed through the same helpers:

- **`DELETE`** was the one method whose `orElseThrow` was not converted. Measured in owner mode with
  no credential: every other method answered `401`/`401`, and `DELETE` answered `401` hidden /
  `404` absent — the unauthenticated oracle, on one method.
- **The `.meta` surface** was a verbatim copy of the pre-masking pattern: `403` hidden / `404` absent
  for every method, `401` / `404` anonymously. `/x.meta` is a total function of `/x`, so this
  restored the oracle for the entire storage.
- **The `.acl` surface**, the same — and this one answers the question most directly, because under
  WAC "has an own ACL" is very nearly the same fact as "exists".
- **The pre-body preconditions.** `requirePutPrecondition` and `checkIfMatch` answered `428`/`412`
  with no authorization at all, and the write pre-filter does not stop them because it is
  deliberately permissive. Measured with an append-only grant: `PUT /drop/taken` → `428`,
  `PUT /drop/free` → `201`, on IRIs whose `GET` was masked to `404` — existence *and* the entity-tag.
  They now skip for a caller who may not read; the authoritative comparison was always inside the
  transaction anyway.
- **`POST`** disclosed existence and *type*: `405` for a data resource, `201` for a container, `404`
  for nothing — and the masked `Allow` header on that `405` said "nothing is here" while the body of
  the same response named the type. `authorize` now precedes the type check.
- **The subscription topic gate**'s comment claimed `canRead` doubles as an existence test. True for
  `OwnerAuthorizer`; false under WAC, where a container's `acl:default` makes an *absent* child
  readable. Measured: subscribing to a hidden topic → `404`, to an absent sibling → **`201 Created`**,
  and the subscription was stored. Now gated on readability **and** existence.

## Tests that passed for the wrong reason

The pass was as valuable here as on the code, and each of these has been replaced or repaired:

- `BlobIoOutsideTheLockTest.anAbortedWriteLeavesNoStagedBytesBehind` PUT a *container* body, which
  stages nothing at all — it asserted about a scenario in which the code under test never ran, and
  never looked in the blob store. It would have passed with the sweep deleted outright. Replaced
  with one that counts blobs across a denial, a stale precondition and a type change.
- `ExistenceOracleTest.subscribingDoesNotDiscloseWhetherTheTopicExists` used a loopback inbox, which
  the delivery policy refuses *before* the topic gate — so both sides returned `400` and the
  assertion held without the gate ever running. The class now allow-lists localhost.
- `JsonLdContextPolicyTest.anOperatorAllowListIsNotDiscardedWhenRdfIoIsFirstUsed` triggers
  `RdfIO`'s static initializer, which has already run by then in a single-JVM surefire run. Measured:
  it passes identically with the if-absent guard reflectively defeated. Left in place — it documents
  the finding and costs nothing — but it is not the guard's regression test, and this note is.
- `Tdb2RdfStoreTest` and `NestedUnitOfWorkTest` each assert "the transaction must be ended, not
  merely aborted" via `inUnitOfWork()`, which `abort()` itself already clears. The assertion cannot
  distinguish the two, and instrumentation showed `dataset.end()` executing **zero** times in 125
  units of work on both backends — Jena's `commitExec`/`abort` call `_end()` internally. The guard is
  kept (the published contract is begin/commit/**end**), but the tests pin a message, not a
  mechanism.

## What was checked and could not be broken

Worth recording, because it is the part that says which claims are safe to rely on:

- **`JsonLimits.requireBounded`'s size accumulator is a genuine lower bound.** 4,000 random trees
  plus targeted cases — 200-character member names, non-ASCII, astral surrogate pairs, heavily
  escaped strings, thirteen number shapes — produced **zero** overcounts against
  `utf8Length(value.toString())`.
- **The depth semantics match the byte scan exactly** for every shape, over a 1..70 sweep.
- **`MAX_NESTING_DEPTH - 2` is exactly right**, measured through the real service: the deepest
  accepted body is 64, renders at 64, and PUTs back; 65 is refused.
- **`requireUnchangedContent`'s `binaryKey`-identity argument holds**: `blobs.write` is called from
  exactly one place, always with a fresh key, and no path rewrites a key in place.
- **N3's core guarantee holds on real TDB2**, not only in memory — which nothing in the suite
  exercises. All five semantics were re-measured there.
- **Base58** round-trips the empty array, one/two/three zero bytes, a high-bit value, a 32-byte key
  with a leading zero, a 34-byte multicodec value and the canonical Bitcoin WIF vector; and for a
  non-zero value the new expression is algebraically identical to the old, so nothing that worked
  before is broken.

## Left open, deliberately

- **`::ffff:0:a.b.c.d` (IPv4-translated), ISATAP and Teredo** are still not unwrapped by
  `OutboundFetchPolicy`. Measured and assessed: the translated prefix is not routable anywhere;
  ISATAP needs a host that has an ISATAP interface *and* an attacker who knows the site prefix;
  Teredo cannot carry a private destination. 6rd uses an operator-chosen prefix and cannot be
  recognised generically.
- **`JsonLdSecurity`'s policy is process-global**, so two `LwsComponents` in one JVM share it,
  last-install-wins. Production has one; the test suite has many. Recorded rather than fixed, because
  making it per-instance means threading it through Jena's global `RIOT` context, which is where Jena
  puts it.
- **Masking makes an append-only client unable to see what it created**: it `PUT`s, gets `201` and a
  `Location`, and every later request for that IRI says `404`. That is the honest consequence of
  keying the mask on Read, and the alternative — treating "I created it" as read permission — is an
  authorization change, not a status-code one.
