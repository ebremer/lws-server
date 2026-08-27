# TODO — lws-server

Derived from `REVIEW.md` (2026-08-26, commit `33a3bb4`). IDs in **bold** reference findings there.

Ordering is by *risk × reachability*, not by area. Items inside a priority band are listed in the order they should be done — several share a root cause and are cheaper together, which is what the **batches** are for.

**Status legend:** `[ ]` open · `[~]` in progress · `[x]` done
**Effort:** S ≈ under a day · M ≈ a few days · L ≈ a week or more

---

## Resume here — state as of 2026-08-27 (late)

**Done — Batches A through S. Every code item in P0, P1, P2 and P3 is closed, and so is the whole
test band.** Batches O, P, Q, R and S closed **N1, N2, N3, N4, N5**, a new **N6**, the
existence-oracle item that was the last open code entry in the long tail, all seven P3 test-band
items, and the first ten of the low tail. Each is marked in its `REVIEW.md` heading, and the
"Fixed:" sections at the end record what changed, why, and where a fix deliberately departed from
the suggestion. **Read those before re-deciding anything** — several suggestions in this file were
measured and found wrong, and one of them (N1) turned out to be describing an unreachable hazard
that was hiding a worse bug.

**Build:** `mvn -o clean test` → **521 tests, 0 failures** (366 at the start of this batch band).
`mvn -B verify` additionally runs the dependency-convergence enforcer.

**Batch T — an adversarial pass ran over Batches O–S and is the first thing to read.** Four read-only
skeptics, three verdicts of UNSOUND, and every defect measured rather than argued. Most of what it
found had been introduced *by* this band: every refused write leaked its bytes (10 MB from five
ordinary 412s, and the quota went fail-open), the N2 hoist reopened a value oracle one method over
from the one Batch Q closed, `Tdb2RdfStore` could orphan a write transaction and block every write in
the server permanently and silently, and fixing `Last-Modified` broke `If-Modified-Since`. Five more
oracle surfaces Batch Q had claimed were closed were not. All fixed; the account is in `REVIEW.md`'s
Batch T section, including three tests that were passing for the wrong reason and what was
deliberately left open.

**The whole remediation is still uncommitted, deliberately** — the last commit is `33a3bb4`, the
*pre*-remediation code. Never read a file with `git show`: the committed version is the version
every finding was written against, and it is now very stale. The tree is the only copy, so
`git checkout .` or `git stash` would destroy the work.

---

### What is left

**1. The low/nit tail — 53 items.** An inventory was taken against the current code (not the review
text): of the ~65 low findings and 19 nits, **47 were already closed** by the H/M work, 3 do not
apply, and 63 were genuinely open. Batch S took ten. The remaining 53 are listed in
`scratchpad/recon/still_open.md` and in the review's own Low-findings section. The ones most worth
doing next, in order:

- `LwsOpenIdValidator` seeds its signature-algorithm allow-list from the **token's own header**,
  making the key-selector check tautological — and it cannot verify EdDSA ID tokens at all, though
  the codebase has an Ed25519 verifier.
- `SsiCidValidator` accepts any `verificationMethod` carrying a matching `kid`, ignoring the
  `authentication` verification relationship.
- `SamlValidator` loads trust anchors as bare public keys, discarding certificate validity dates.
- `AuthenticationFilter` downgrades a malformed or unknown-scheme `Authorization` header to
  anonymous instead of answering `401`.
- `OutboundFetchPolicy` discards the vetted `InetAddress` so the fetcher re-resolves (DNS-rebinding
  TOCTOU). The *ranges* half of that finding is fixed; this half is not.
- `NotificationEmitter` drops `clientId` when reconstructing the subscriber principal, so a
  client-constrained grant never applies at delivery. Needs `Subscription` to persist it.
- `WebhookDispatcher.close()` neither drains the pool nor closes its `HttpClient`, and races
  `rdfStore.close()`.
- `FileSystemBinaryStore` never fsyncs; crash-leftover `.lws-*.tmp` files are never reaped.
- The `LwsConfiguration` validation gaps (L45a–e) and the ACME ones (L46a–b).

**2. Two `WacAclService` L-band items, deliberately deferred with their designs recorded** in
`REVIEW.md`'s Batch O section: requiring `rdf:type acl:Authorization` (which needs a startup sweep
over every ACL graph plus a migration-time repair, or it can brick a subtree with no HTTP recovery),
and dropping the local group cache (which needs an explicit per-decision read cap first, and needs
N3's fix — now landed — under it).

**3. H10's separate-origin item**, assessed in Batch I and deliberately left: in LWS a resource's IRI
*is* its address.

**4. What the oracle fix does NOT close**, stated in Batch Q: under WAC the anonymous `401`/`404`
split still discriminates by where ACLs sit, and no status-code masking can fix it.

---

### Where the long-form working notes are

Kept outside the repo, because they describe unfixed findings with file:line pointers and
`SECURITY.md` gates publication on exactly that:

```
C:\Users\Erich Bremer\.claude\projects\D--lws-lws-server\review-artifacts\
```

Its `README.md` says what each file is. The short version: `recon/` holds the per-finding design
**and the adversarial critique of that design** — read the critique first, because for four of the
six it is the part that mattered — plus the test-band work order and the full low/nit inventory;
`adversarial/` holds the four verdicts from the pass over Batches O–S, carrying the probe output
(byte counts, status codes, bytecode offsets) that `REVIEW.md`'s Batch T section only summarises.

Nothing there is needed to continue — it is all folded into `REVIEW.md` and this file — but it is
where the numbers and the reasoning live if a decision needs re-opening.

---

### Working conventions (followed throughout; keep them)

1. Fix secure-by-default and give the relaxation a config key — never fail open to keep something
   working. Several fixes are deliberately breaking; each has a "Note for operators" in `REVIEW.md`.
2. When a fix breaks a test, change the test to opt in explicitly rather than weakening the default.
3. **Every new config key must be added to `lws.example.properties`.** Verify both directions:
   ```bash
   grep -oE '"lws\.[a-z0-9.\-]+"' src/main/java/com/ebremer/lws/server/LwsConfiguration.java \
     | tr -d '"' | sort -u > /tmp/code.txt
   grep -oE '^#?\s*lws\.[a-z0-9.\-]+' lws.example.properties \
     | sed 's/^#\s*//' | tr -d ' ' | sort -u > /tmp/doc.txt
   comm -3 /tmp/code.txt /tmp/doc.txt   # only `lws.properties` (a filename constant) should differ
   ```
4. Update `README.md` / `COMPLIANCE.md` wherever a fix falsifies a claim they make.
5. Keep `core` free of a dependency on `auth` (`auth` already depends on `core`).
6. **Deviate from this file's suggested fix when the code disagrees, and say so in `REVIEW.md`.**

### What the sessions learned about how to work here

- **Measure the library, not the finding.** This is now the single highest-value habit, and it has
  inverted a finding three times. The JSON provider caps nesting at 1,000 and reports it as a bare
  `RuntimeException` that every catch in the tree let through, while its *writer* has no cap at all
  — that asymmetry, not the depth, is N5. Jena's `Txn` aborts a transaction it did not begin, and
  every `RDFConnection` call is such a frame — probed, and the probe showed a swallowed throw losing
  the write before it and autocommitting the write after it. And `RdfIO`'s static initializer was
  re-installing the refuse-all JSON-LD policy *after* the operator's allow-list, so
  `lws.jsonld.allowed-context-hosts` did nothing at all — two `identityHashCode` calls found it.
- **Reproduce before fixing, and run the new regression test against the unfixed code.** N5's size
  test did not fail against the unfixed code — it *hung the server*, which is the denial of service
  the finding describes.
- **Run an adversarial pass over every design before writing it.** In this band it caught: an
  off-by-two that would have made the server hand out linksets it then refused to accept back; a
  blob-staging design that deleted live blobs on its own fallback path; an oracle fix whose central
  predicate was an existence proxy under WAC; and an N1 fix that would have introduced a
  pre-authentication outbound-fetch primitive. Four designs, four fatal defects, all found before a
  line was written.
- **A fix's own blind spot is reliably the branch next to the one you were looking at.** N2's first
  cut hoisted a read unconditionally and turned a `415` into a `409` on the RDF branch; the oracle
  fix left OPTIONS discriminating in the *opposite* direction, and left the servlet's pre-body write
  filter with its own copy of the 401/403 decision.
- **Subagents: give them disjoint files, forbid `src/main` and `mvn`, and hash the tree afterwards.**
  Four bands have now held. Earlier ones did not — a "read-only" agent twice reverted a security fix.
- **Do not use `python ... > file` patterns that truncate on failure.** One such script emptied an
  untracked test file mid-session; it was recovered by decompiling the `.class` from the last green
  build, which worked but cost the javadoc of three methods.

**Environment gotcha:** the suite leaks a TDB2 temp directory per run. `TestDirs` sweeps its own
`lws-test-` prefix on the next run, but ~15 GB of pre-`TestDirs` directories under other prefixes
(`lws-ops*`, `lws-it*`, `lws-ui-test*`, …) are still there from earlier sessions and nothing sweeps
those. A TDB2 `BlockMgrMapped.segmentAllocate: Segment = 0` failure in `@BeforeAll` means *out of
disk*, not a code bug. Sweep with:
```bash
find "$LOCALAPPDATA/Temp" -maxdepth 1 -name 'lws-*' -mmin +60 -print0 | xargs -0 -r rm -rf
```

**Before making this repo public:** `REVIEW.md`, `TODO.md` and `REVIEW-lws-server.md` describe the
remaining unfixed findings with file:line pointers. `SECURITY.md` says so explicitly.

---

## P0 — Before this server touches an untrusted network — **DONE 2026-08-26**

Both remotely reachable takeovers are closed. Kept as the record of what was done.

### Batch A — Reserve the resource namespace (one root cause, six findings)

`.acl`, `.meta` and `/.lws` are enforced by the *router* but not by the *create path*, and WAC ACLs are addressed by public IRI. Fixing the addressing fixes the escalation, the unreachable-resource bug, and three protocol bugs at once.

- [x] **C2** · **DONE 2026-08-26** · One reserved-path predicate: `Iris.ACL_SUFFIX`/`hasReservedSuffix` (config-free, so `core` still needs nothing from `auth`) plus `LwsConfiguration.isReservedPath` (the system prefix is configurable). `ResourceService` returns 409 from `chooseName` — on the *sanitized, composed* path, before the de-dup loop, because sanitizing can create a reserved name (`x.acl-` trims to `x.acl`) and because the de-dup loop would otherwise mint `x.acl-2` — and at the top of `put()`, covering the replace branch so a legacy `.acl` resource cannot be written over. Refused rather than renamed: a silent rewrite would answer a denied request with 201 + Location. `LwsResourceServlet` drops the `Allow` header from this 409.
- [x] **C2** · **DONE 2026-08-26** · ACL graphs moved to `urn:x-lws:acl:<targetIri>`; `aclIriFor` survives as the advertised address only (Link `rel="acl"`, `Location`, `handleAcl` routing). Resource IRIs are always built from the http(s) base, so no request can name a graph in that namespace.
- [x] **C2** · **DONE 2026-08-26** · `LegacyAclMigration`, run before `bootstrapRootAcl`. Migrates legacy `<base>/*.acl` graphs with **no registry entry**, quarantines those that have one (that entry is the discriminator: `putAclFor` is the only writer that makes a graph without one), and prunes ACLs whose target no longer exists. OWNER mode only reports. The ordering means an already-exploited store recovers by itself — the planted root ACL is quarantined, so bootstrapping rebuilds the root from `lws.owners`.
- [x] **C2** · **DONE 2026-08-26** · Regression tests in `ReservedNameTest`, `LegacyAclMigrationTest` and two additions to `WacAclServiceTest` — including that the C2 payload written straight into `<base>/shared/.acl` changes no decision.
- [x] **H18** · **DONE 2026-08-26** · Same guard; `Slug: report.meta` and `Slug: .meta` are refused with 409.
- [x] **L17 / L-`/.lws`** · **DONE 2026-08-26** · `/app` and `/callback` and their subtrees are reserved. `Pac4jSupport.CALLBACK_PATH` now derives from `LwsConfiguration.CALLBACK_PATH` so the two cannot drift.

### Batch B — Bind signatures to claims

- [x] **C1** · **DONE 2026-08-26** · `signatureBindsAssertion` requires: one `Assertion` and one `Signature` in the document; the signature a **direct child** of that assertion; exactly one `Reference`, whose URI is literally `#<ID>`; that ID unique in the document and resolving back to the same node; and an enveloped-only transform chain. *(Two corrections to the suggestion above, both measured: `context.getElementById` is the **wrong map** — the dereferencer prefers `Document.getElementById`, so the suggested check fails closed on every honest credential and could pass while a different element was digested; and `secureValidation` permits both **XPath** dialects, so the transform allow-list is what actually closes that door.)*
- [x] **M1** · **DONE 2026-08-26** · `firstChild` replaced by `directChild`, a real sibling walk. Its reachable case — a `SubjectConfirmation/NameID` ahead of the subject's own, inside one properly signed assertion — survives the single-assertion rule and is regression-tested.
- [x] **C1** · **DONE 2026-08-26** · Seven XSW regression tests plus six companions; `SamlValidatorTest` goes from 5 to 18. Four of the new tests authenticate as the attacker when run against the pre-fix validator.
- [x] **C1** · **DONE 2026-08-26** · `audienceOk` also fixed: several `AudienceRestriction` elements are a **conjunction** (SAML Core §2.5.1.4), not one flat disjunction, and configuring `lws.saml.audience` now requires a restriction rather than checking one only if present.
- [x] **Interim** · **NOT NEEDED** · Never carried out, and now moot: the three `lws.saml.*` keys ship commented out, so the suite is inactive by default and there is no README text to remove.

### Batch C — Credential binding (do H1–H3 as one change) — **DONE 2026-08-26**

- [x] **H1** · Reject a `cnf`-bearing token presented under `Bearer`. Added `DpopValidator.isSenderConstrained(token)`; the filter answers 401 with a `DPoP` challenge, and checks *before* validation so a downgraded token cannot drive an outbound fetch. `lws.dpop.require` added. README corrected.
- [x] **H2** · Added `AudiencePolicy` (new `lws.audience` / `lws.audience.require`), consulted by all three JWT suites. A wrong `aud` is always refused; the flag only governs an *absent* one. COMPLIANCE.md:78 updated. `azp` left informational — see the REVIEW.md note.
- [x] **H3** · `JwsSupport.temporalClaimsValid` replaced `notExpired`: enforces `exp`, rejects post-dated `nbf`/`iat`, caps `exp - iat` at `lws.token.max-lifetime-seconds`. Both self-signed suites also enforce the audience policy. The `jti` replay cache was deliberately skipped (these are multi-use access tokens, not per-request proofs).
- [x] **M3** · **DONE 2026-08-26** · The trust `ASK` now walks `?subject (did:service|lws:service) ?svc` with `setIri("subject", sub)`, so a provider named by a neighbour the profile happens to describe no longer confers trust. Regression-tested with a document that `foaf:knows` a genuinely trusted profile.
- [x] **M12** · **DONE 2026-08-26** · `OidcLoginPage` now calls `openIdSubjectTrustsIssuer` before signing anyone in. *(Deliberately narrower than "run it through `app().validator()`": pac4j has already verified signature, issuer, expiry, nonce and audience, and re-applying the API's audience policy would reject the console's own token, whose `aud` is the console's client id because the console is a different relying party. The missing guarantee was only the trust step.)*
- [x] Tests added: `AuthenticationFilterTest` (Bearer downgrade, `lws.dpop.require`, unbound-token contrast), foreign/absent `aud` rejection across all three suites, century-lifetime rejection, `DidKeyTool --audience` round-trip.

### Batch D — One hardened outbound HTTP client

Every finding here is "the guard exists but this path doesn't use it."

- [x] **H5** · **DONE 2026-08-26** · `HttpDocumentLoader` now uses `Redirect.NEVER` and follows hops itself, re-running `fetchPolicy.permits` per hop (cap 5) with connect/request timeouts and a 2 MiB cap. `DocumentLoader.loadRdf(url)` was added and both `RDFDataMgr.loadModel(untrustedUrl)` call sites — the OIDC subject document and the WAC `acl:agentGroup` document — go through it. Covered by `HttpDocumentLoaderTest`. *(A Jena `RegistryHttpClient` registration is no longer needed for these paths, but would still be worth adding as a backstop if a future caller reaches for `RDFDataMgr` directly.)*
- [x] **H6** · **DONE 2026-08-26** · `OutboundFetchPolicy.forDelivery(config)` (`lws.webhook.*`) is threaded into `WebhookDispatcher` and `SubscriptionService`, and into `AccessService` as a predicate (keeping `core` free of an `auth` dependency). Inboxes are refused twice: a 400 at creation, and again before each delivery attempt (the policy resolves DNS, so a host can change between the two).
- [x] **H6** · **DONE 2026-08-26** · `SubscriptionService.describe()` strips `lws:failureCount` from the client-facing representation (still tracked server-side for deactivation). `active` is retained but only flips after `max-consecutive-failures`, so it carries no per-request signal.
- [x] **H9** · **DONE 2026-08-26** · `JsonLdSecurity` installs a refusing Titanium `DocumentLoader` from `RdfIO`'s static initializer (so it holds even without the full server), widened by `LwsComponents` to `lws.jsonld.allowed-context-hosts`. Permitted fetches are https-only, 512 KiB-capped, time-bounded and non-redirect-following.
- [x] **H4** · **DONE 2026-08-26** · `validate` reordered to audience → JWKS/discovery → signature verification → subject fetch; the fetch goes through the hardened loader; failed trust lookups are negatively cached for 60s; discovery now uses explicit 3s/5s timeouts instead of the `resolve(Issuer)` overload's zero (unbounded) ones.
- [x] **H8** · **DONE 2026-08-26** · A `ServiceGuard` visitor now walks expressions too (`FILTER`/`BIND`/`LET`, sub-select `HAVING` and projections), recursing into the pattern `EXISTS`/`NOT EXISTS` carries via `ExprFunctionOp` — the only expression type that can hold one. Six bypass shapes regression-tested. *(Jena 5.6 has no three-arg `ElementWalker.walk`, and the algebra walk has the same expression blind spot, so the syntax+expression walk is the complete fix.)*
- [x] **H16** · **DONE 2026-08-26** · The *inputs* moved, not the decision: `Authorizer.prepare` resolves an authorization's remote inputs before the transaction opens, and every in-transaction `authorize(...)` stays where it was and stays authoritative (memoising the answer would have made a committed revocation invisible to the write it permitted). `RdfStore.inUnitOfWork()` — TDB2's own per-thread state — lets `WacAclService` refuse to dereference a group document while a transaction is open. A failed load is no longer cached as "this group has no members" (it was, for the full 5 minutes, storage-wide); it goes in a short-TTL failure cache instead. Added a per-decision fetch budget, and gave `HttpDocumentLoader` a 20 s budget across all redirect hops plus an explicit deadline on the asynchronous exchange so the budget finally covers the response body (`HttpRequest.timeout()` never did — measured). *(A naive hoist of `authorize` ahead of `registry.find` was rejected: `OwnerAuthorizer` denies any IRI with no registry entry, turning seven existing `404` assertions into `401`.)*
- [x] · **DONE 2026-08-27 (Batch R)** · `InboxSsrfTest`, over real HTTP in the DEFAULT posture (no `lws.webhook.allowed-hosts`): seven refused inboxes — cloud metadata, RFC 1918, loopback, carrier-grade NAT, the IPv4-mapped and 6to4 wrappings of the metadata address, and a `file:` URL — each 400 with no `Location`, and the whole subscription listing byte-identical before and after, because a stored subscription the server merely never delivers to is still a stored, attacker-chosen URL. Plus a control on a permitted address, using an IP literal because the policy fails CLOSED on a name that does not resolve. The redirect half is covered by `auth/HttpDocumentLoaderTest`, where the hop-by-hop re-check lives.

### Batch E — Bound the request before you trust it — **DONE 2026-08-26**

- [x] **H12** · **DONE 2026-08-26** · `lws.max-request-bytes` (default 64 MiB) enforced in `HttpSupport.readBody` — `Content-Length` first, then one byte past the limit for chunked bodies — at every read site including the two servlets that streamed straight into `Json.createReader`. 413/429 added to `reasonPhrase`.
- [x] **H12** · **DONE 2026-08-26** · `requireWriteBeforeBody` runs on POST/PUT/PATCH before the body is read. Deliberately permissive (rejects only when denial is certain); the authoritative check still happens inside the write transaction.
- [ ] **H12** · S · *(Not done — Jetty 12's `HttpConfiguration` has no request-body limit; `setMaxFormContentSize` covers forms only. The application-level cap above is the real control.)*
- [x] **M17** · **DONE 2026-08-26** · New `core/JsonLimits.requireBoundedNesting` refuses a body nested past 64 levels in one non-recursive scan, *before* the parser sees it, so the overflow cannot happen rather than being caught afterwards; `StackOverflowError` is added to each parse site's `catch` as a backstop only. Applied at all six request-body parse sites, not just the two named — `AccessService`, `LinksetService`, `SearchIndexServlet` and `SubscriptionServlet` reach the same parser the same way. *(64 is measured, not guessed: the deepest document the server generates for itself is its own JSON-LD projection of a stored graph, and Jena flattens into `@graph`, so a 500-element `rdf:List` measures depth 3.)*
- [x] **M37** · **DONE 2026-08-26** · `POST /.lws/subscriptions` requires a JSON content type before the body is read; `requireJsonContentType` moved from `AccessServlet` to `HttpSupport` so the two cannot drift. The topic cap (`MAX_TOPICS` = 64) was already in place from H6 and now has a test.

### Batch F — Fail-closed configuration — **DONE 2026-08-26**

- [x] **H17** · **DONE 2026-08-26** · Only `NoSuchFileException` is tolerated; any other `IOException` or a malformed Unicode escape refuses to start. The read moved into `mergeOptionalFile(Properties, Path)` so it is testable at all, and the `isRegularFile` guard is gone — it asked the same question the catch then pretended to ask again.
- [x] **H22** · **DONE 2026-08-26** · Reproduced end to end first (a self-minted did:key held read+modify+create+delete over the whole storage after the documented hardening step, and after a switch to WAC). `DefaultAccessPolicy.canControl` loses its open-mode disjunct, `AccessServlet.isController` requires `!isOpenMode()`, issuance is refused in open mode, `storage`/`target.value` are bounded at creation, and the issuer is re-checked at every evaluation via a `Predicate<String>` wired to the BASE authorizer. Stored/inert grant counts logged at startup. *(Per distinct ISSUER, not per grant: measured +190% in owner mode per grant versus under 1% per issuer. The issuer epoch was rejected — under WAC, controllers change by ACL edit, which never moves it.)* **Blocking new finding fixed with it:** `bootstrapRootAcl` wrote a public-full-control root ACL in open mode and never revisited it, so configuring owners later did nothing; the development ACL is now marked and rebuilt once owners exist.
- [x] **M9 / prior-9** · **DONE 2026-08-26** · **One key, not a profile.** `lws.dev.open` (default false) permits the two development postures; `lws.public-read` now defaults to false; dev-login is refused off-loopback at startup and per request, and outright behind a proxy. *(`lws.profile=production` was rejected: a profile that only tightens when set is a no-op for exactly the operator it protects. Also fixed a fail-open in `isLoopbackBaseUri` — it matched the host string, so `[2001:db8::1]` and `127.example.com` counted as loopback and escaped the HTTPS requirement.)* Sixteen test classes opt in, seven with `lws.dev.open` and nine with an owner.
- [x] **M9** · **DONE 2026-08-26** · Dropped. The field was also a second lockdown-survival bug — stamped at creation, so resources made while `lws.public-read=true` stayed world-readable after it was set to false. `canRead` consults the config directly; per-resource opening is an access grant with `assignee: foaf:Agent`, per-agent is WAC. *(A real control path was weighed in three shapes and rejected: each mints a second control surface, and the `.meta` variant would make WRITE imply CONTROL.)*

---

## P1 — Correctness and data integrity

### Batch G — Make writes atomic — **DONE 2026-08-26**

- [x] **H13 + H14** · **DONE 2026-08-26** · `Iris.newBinaryKey()` mints a sharded UUID; `Iris.binaryKey(path)` is gone. Fixes case aliasing, the file/directory collision (**M24**), illegal characters and reserved device names. Existing path-derived keys keep resolving and retire as resources are rewritten — no migration.
- [x] **H13** · **DONE 2026-08-26** · No new `BinaryStore` methods were needed: with opaque keys a fresh key *is* the staging area. `ResourceService` tracks `BlobChanges` per write — staged keys deleted if the transaction throws, superseded keys only after it commits, `deleteContent` recording keys rather than unlinking mid-transaction.
- [x] **H23 + M18** · **DONE 2026-08-26** · New `core/IfMatch` carries the raw header into the service; the compare-and-swap runs inside every write lambda, **after** `authorize` (RFC 9110 §13.2.2 ignores a precondition on a request that would have failed anyway). `LinksetService` needed more than a parameter: its read-modify-write really did span three transactions plus a fourth in `resources.stat`, so a new private `update(path, ifMatch, UnaryOperator<JsonObject>)` does the whole thing in one `rdf.write` — a linkset PUT went from five transactions to one. *(Deviation: `ResourceService` gained `stat(RDFConnection, String)` rather than `LinksetService` gaining its own `ResourceRegistry`.)* The servlet keeps an early check to bound the body read, now honestly advisory and reordered after `requireWriteBeforeBody`; `handleDelete` has no body to bound and stopped pre-checking. **Second lost update found and fixed:** `If-Match` against a resource that does not exist was *ignored*, so a `PUT` naming a version deleted in the window created it and answered 201.
- [x] **H24** · **DONE 2026-08-26** · New `core/ResourceCleanup` (`onDelete(RDFConnection, String)`), invoked inside the delete transaction per subtree member with no `try`/`catch`; `WacAclService` and `LinksetService` implement it instead of `ResourceEventListener`. Both take the caller's connection: on TDB2 a nested `rdf.write` joins the enclosing transaction and looks fine, while `RemoteSparqlRdfStore` would silently split the delete into two commits. The notification emitter and search index stay post-commit — the first would be denied every `acl:agentGroup` subscriber by the `inUnitOfWork` refusal, the second nests a JVM build lock inside the writer lock. **Pre-existing bug fixed with it:** `conn.delete` on an absent ACL graph 404s on the remote backend, which was harmless while swallowed and would have aborted every delete of an ACL-less resource once it was not.
- [x] **H23** · **DONE 2026-08-26** · `ConditionalWriteTest` — eight writers held at a latch, all carrying the same tag. **Written and run against the pre-fix code first: all eight won** (`[204 × 8]`) on PUT, merge-PATCH and linkset PATCH alike. `core/DeleteAtomicityTest` pins H24's half. The suite now has its first concurrent tests.

### Batch H — Container semantics — **DONE 2026-08-26**

- [x] **H15** · **DONE 2026-08-26** · A `touch` helper bumps `modified` and recomputes the persisted tag together wherever membership changes; `read()` returns the stored value instead of hashing the rendering. Container responses now carry `Cache-Control: private, no-store`, since the listing is per-principal. Round-trip covered by test.
- [x] **M14** · **DONE 2026-08-26** · PUT with a body to an existing container is `409` (its representation *is* its membership, so there is nowhere for the triples to go); a bodiless PUT returns `204` and changes nothing at all, entity-tag included. The second half matters on its own: bumping the tag for a write that stored nothing left a client holding the tag it had just read, whose next conditional write would be refused `412` for a change that never happened.
- [x] **M13** · **DONE 2026-08-26** · On PUT, an explicit `Link: rel="type"` that contradicts the IRI's own shape is `400` — in **both** directions, which is slightly wider than the finding: one rule is easier to state than two, and a non-container hint on a `/`-terminated path was the same silent-substitution disease. POST is exempt (it appends the slash itself from the type it resolved) and is regression-tested as such. The guard went into `resolveType`'s `isPut` parameter, which existed and had never been read.
- [x] **H21** · **DONE 2026-08-26** · **Reproduced first — the review had it as UNVERIFIED, and it is real.** Measured against Jena 5.6: one subject serializes as a flat node object, two as `{"@graph":[…]}`; merging at the top level makes that a *named graph* node, and a three-triple two-subject resource came back as **one** triple on a fresh blank node, answered `204`. Withdrawn rather than normalized: `415`, and dropped from `ACCEPT_PATCH`. Making it work would ask the client to write its patch against a different document shape depending on how many subjects the resource happens to have — exactly the argument `patchJsonPatch` already makes for declining RDF. The conformance departure (the ED makes merge patch the one required PATCH format; it is still supported on JSON resources and linksets) is recorded in `COMPLIANCE.md`, and is now cheaply reversible because M38's guard turns the failure into a `400` rather than destruction.
- [x] **M38** · **DONE 2026-08-26** · `RdfIO.parse` now parses into a `DatasetGraph`, refuses if any **named graph carries data**, then reduces to the default graph. *(Deviation: not "TriG output-only". Refusing only the lossy subset keeps TriG usable for documents that genuinely are one graph, and putting the guard at the parser rather than in a format table also covers JSON-LD named graphs — a route a format table would have missed.)* Measured first: Jena's own 2-subject JSON-LD output stays in the default graph, so no legitimate shape is affected — while the H21 merged document lands in a blank-node-named graph, so **the same guard backstops H21 too.**

### Batch I — Browser surface — **DONE 2026-08-26**

- [x] **H10** · **DONE 2026-08-26** · `HttpSupport.setContentSecurityHeaders` adds `nosniff` + `Content-Security-Policy: sandbox; default-src 'none'` to every non-RDF read, and `Content-Disposition: attachment` for the active-content set. The stored media type is preserved rather than rewritten, so clients still see the right type while browsers will not execute it in this origin.
- [ ] **H10** · L · *(Preferred long-term)* Serve user content from a separate origin from the console. **Assessed 2026-08-26 and deliberately left open:** in LWS a resource's IRI *is* its address, so moving user content to another origin either changes resource identity or introduces a redirect and a second trust boundary, and it interacts with WAC's `acl:origin` plus DNS and certificate provisioning an operator has to do. Not a code change of this size. H10's shipped half (`nosniff` + CSP sandbox + `Content-Disposition: attachment`) is what stands in for it.
- [x] **H11** · **DONE 2026-08-26** · Registered in `LwsWebApplication.init()`.
- [x] **H11** · **DONE 2026-08-26** · All five are POST forms now; a cross-site submit is covered by `LwsUiTest.crossSiteFormSubmitIsRefused`.
- [x] **H11 / L-cookies** · **DONE 2026-08-26** · `HttpOnly` + `SameSite=Strict` in both bootstraps; `Secure` only when the server itself serves HTTPS (forcing it on a plaintext dev server would stop the cookie being sent). The bare launcher also got the 30-minute session timeout Spring already had (**M25**).
- [x] **M29** · **DONE 2026-08-26** · `DEPLOYMENT` by default plus `setUnexpectedExceptionDisplay(SHOW_INTERNAL_ERROR_PAGE)`. *(Deviation: not an unconditional override. `DEVELOPMENT` from `super` is ambiguous — "an operator asked" versus "nobody said anything" — so the override looks for the operator's own words in the three places Wicket looks, keeping Wicket's switch working instead of removing it, and avoiding an `lws.*` key that would be a second spelling for the same setting.)*
- [x] **M30** · **DONE 2026-08-26** · Both. The `invalidateNow` half matters more than it looks: clearing `principal` left Wicket's page store alive, holding pages rendered while signed in whose stateful callbacks were still invokable at their guessable URLs.
- [x] **M11** · **DONE 2026-08-26** · The `removeAcl` re-check landed with H11's form conversion; this batch did the part that matters — `putAclFor`/`deleteAclFor` now take a principal and refuse anyone without `acl:Control`. The unchecked forms survive as `putSystemAclFor`/`deleteSystemAclFor` for writes the server owns (bootstrap, migration, fixtures), named so a call site says which one it is.
- [x] **M20** · **DONE 2026-08-26** · The mandatory-precondition rule moved into `ResourceService.put`, which both entry points go through, and `ui/BrowsePage` now passes the entity-tag of the version its page rendered. Batch G's `IfMatch` parameter meant this was a guard plus a call-site change rather than a signature migration — and it confirmed the Batch G decision to keep `expectedEtag` off `WriteRequest`. `core` still holds no servlet or framework type: a status code is not one, and `LwsException` has carried them from here since the beginning. One test (`WriterLockAuthorizationTest`) opts in explicitly by reading the tag first.

### Batch J — Notifications correctness — **DONE 2026-08-26**

- [x] **H7** · **DONE 2026-08-26** · Anonymous creation refused by default (`lws.subscriptions.allow-anonymous`); per-subscriber cap (429) and a 64-topic cap; `expires` defaulted and capped by `lws.subscriptions.max-lifetime-seconds`, and a past `expires` is now a 400. `requireManage` moved into `SubscriptionService` and decides via the configured `Authorizer` — it previously failed open in WAC mode (this also closes **M43**).
- [x] **M43 / L39** · **DONE 2026-08-26** · M43 landed with H7. **L39** is fixed here: `listCollection` was an unguarded `listFor(webId)`, and `listFor(null)` matches every subscription whose `subscriberWebId` is null — so any unauthenticated request enumerated every anonymously-created subscription, inbox URLs and topics included. Authentication is now required; a caller sees its own and a storage controller sees all. The decision went into `SubscriptionService.listVisibleTo`, not the servlet, for the reason `requireManage` and the conditional-write rule moved there too.
- [x] **H19** · **DONE 2026-08-26** · New `core/DeleteAudience`, consulted per subtree member before the write transaction; the answer rides on `ResourceEvent.audience()` (a set of **subscription ids**, so an anonymous subscription is representable). The fail-open is gone — no captured audience means nobody. **Note Batch G made this strictly necessary:** H24 moved ACL cleanup *into* the delete transaction, so by emit time the child's ACL is gone and even the "correct" per-resource `canRead` would resolve through the parent. Capturing beforehand stopped being the tidier option and became the only one.
- [x] **M31** · **DONE 2026-08-26** · Cleared and restored around every subscriber-authorization decision. *Cleared* rather than substituted: a webhook delivery genuinely has no origin and declares no purpose, and `originAllowed` refuses without one — the fail-closed direction. Restoring matters and is easy to miss: control returns to the servlet afterwards and the response path still evaluates authorization.
- [x] **M33 / M34** · **DONE 2026-08-26** · All of it, plus a new `DeliveryOutcome` enum carrying the classification. Three new keys (`lws.webhook.threads`, `queue-capacity`, `max-in-flight-per-host`), mirrored in `lws.example.properties`. Regression tests drive a real local inbox and count attempts: 404 asked once, 503 asked `max-attempts` times, 410 asked once and deactivated immediately.
- [x] **M35** · **DONE 2026-08-26** · Default port dropped per RFC 3986 §6.2.3. *(Deviation: `WebhookDeliveryTest` was left alone rather than "fixed" — it uses a non-default port, so the bug is invisible from there whatever it does with the base. A new `WebhookSigningAndKeysTest` verifies against a base it builds itself and covers `:443`, `:80`, a non-default port and a mixed-case host.)*
- [x] **M36** · **DONE 2026-08-26** · Owner-only temp file + `ATOMIC_MOVE` that deliberately does **not** replace, so a process losing the race re-reads the winner's key rather than overwriting one subscribers already verify against. Owner-only is POSIX where available and the `java.io.File` calls (Windows ACLs) otherwise. Both bad-read paths now name the file: **measured** — a 16-byte seed used to surface as `ArrayIndexOutOfBoundsException: arraycopy`, and a malformed one as an `IllegalArgumentException` that escaped the constructor's `catch (IOException)` entirely.
- [x] **M32** · **DONE 2026-08-26** · `all()` is an invalidated in-memory snapshot (version counter read before the load, so a write landing mid-load is not lost). *(Deviation: no topic-filtered SELECT and no event-list hand-off. The SELECT would put the container-prefix rule in a query string as well as in `Subscription.covers`, where the two could disagree, to save a list scan over data already in memory; the event list existed only to amortise the per-event `all()`, which is now O(1).)* Measured with a counting store rather than asserted: fifty matches after priming perform zero further reads.

---

## P2 — Performance, protocol conformance, operability — **DONE 2026-08-27**

Every item in this band is fixed. Kept as the record of what was done; the reasoning, the measured
evidence and every deliberate departure from the suggestions below are in `REVIEW.md`'s
"Fixed: P2" sections.

### Batch K — Auth-path cost and the things on disk

- [x] **M26** · **DONE** · New `core/SecureFiles` writes every persisted secret owner-only *from
  creation* and atomically. POSIX mode as a creation attribute where available; otherwise a
  **replacement Windows ACL** (one ALLOW entry for the file owner) — the `java.io.File` ladder the
  previous helper used cannot revoke read on NTFS and returned false every time, so the ACME account
  key, the TLS domain key and `tls/` were unprotected on the platform this is developed on.
  `WebhookKeys` folded onto the same helper. Note for operators: `<data-dir>/keys` and `lws.tls.dir`
  are *tightened* at startup if they already exist.
- [x] **M27 / M16** · **DONE** · `lws.sparql.mode=REMOTE` refuses to start without
  `lws.sparql.remote.accept-no-transactions=true`, and then requires all three endpoints as absolute
  `http(s)` URLs. Deliberately not subject to the SSRF policy — the documented example is a loopback
  Fuseki. `RdfStore`'s atomicity claim corrected: **only TDB2 makes a unit of work atomic**, and
  `RemoteSparqlRdfStore`'s javadoc now enumerates what REMOTE silently drops (H23's compare-and-swap,
  H24's cleanup-with-delete, H13/H14's blob ordering, M18, the quota).
- [x] **M6** · **DONE** · The DPoP `jti` is claimed by `DpopValidator.claimProof`, called from the
  filter **after** the access token has validated and been found bound to the proof key.
  *The review's suggested fix does not work*: `ath` compares two strings the caller supplies, so
  moving the record past it changes nothing. Cache TTL widened from `maxAgeMs` to the full `iat`
  acceptance window (`maxAgeMs + skewMs`) — a second defect found in the same lines — sized by
  `lws.dpop.jti-cache-size`, and a size eviction is counted and warned about, because an evicted
  unexpired entry *is* a re-opened replay window.
- [x] **M4** · **DONE** · The timeout half was already done. Added: negative caching of discovery
  failures, and — a new finding — **neither outbound leg refused redirects**. `DefaultResourceRetriever`
  opens a bare `URL.openConnection()`, so a policy-approved `jwks_uri` could `302` the server to
  `169.254.169.254` unchecked. Both legs now refuse redirects outright.
- [x] **M5** · **DONE** · `SsiCidValidator` caches subject documents (weight-bounded by characters,
  not entry count) with a short negative cache. `lws.ssi-cid.document-cache-seconds` /
  `...-failure-cache-seconds`. The cost is a bounded key-revocation delay, documented.
- [x] **H20** · **DONE** · Shiro removed from the source entirely — `ShiroSupport`, `LwsRealm` and
  `LwsAuthenticationToken` deleted, the per-request `login()` gone. The `webId() == null` refusal the
  realm performed is kept as an explicit guard. Shiro now arrives only through the **optional**
  `jena-fuseki-main`, so a deployment without the embedded SPARQL endpoint has none at all.

### Batch L — Names, modes, and coming up

- [x] **M15** · **DONE** · `chooseName` caps the sequential probe at 8, then tries up to 4 random
  suffixes, re-checks the reserved namespace and 409s rather than overwrite. At most 12 `ASK`s
  regardless of how many resources share a `Slug`, instead of a quadratic scan under the writer lock.
- [x] **M8** · **DONE** · A fifth `AclMode.DELETE`. Only *grants* draw the distinction (ODRL's
  `modify` vs `delete`); WAC maps it to `acl:Write` because WAC has no delete permission, and the
  owner model treats it like WRITE. All four sites in `ResourceService.delete` moved together so
  `prepare` warms the mode the decision uses. **Breaking:** a grant naming only `modify` no longer
  authorizes `DELETE`, and one naming only `delete` no longer authorizes a rewrite.
- [x] **M28** · **DONE** · `HttpsRedirectFilter` takes a mandatory readiness gate and answers
  503 + `Retry-After` — not a *permanent* redirect to a closed port — until the HTTPS connector is
  up; the ACME path stays exempt. `enableTls` is retried with exponential backoff instead of killing
  an already-started server, and a connector that failed to start is removed. HSTS moved out of the
  plaintext redirect (where RFC 6797 §8.1 requires user agents to ignore it) into `tls/HstsFilter`,
  installed in **both** bootstraps — the Spring one, which the README calls the default, emitted none
  at all. `lws.hsts.max-age-seconds`.

### Batch M — Conditional requests and conformance

- [x] **M21** · **DONE** · An RDF representation's entity-tag is the resource-state tag plus a variant
  token. `IfMatch.namesState` strips a *known* token so a write conditioned on any representation's
  tag still matches, while `matches` stays exact so a cached Turtle is not revalidated against
  JSON-LD. Negotiation moved before the conditional check; `Vary`/`Accept-Patch` set before the 304.
- [x] **M22** · **DONE** · The storage description's tag is a hash of its canonical JSON, computed
  once at construction — every input is a final config field. The blank-node instability is gone
  because the tag is no longer `Etags.forModel`, and `forModel` now says in its javadoc that it is
  only meaningful for a ground graph. The servlet's hand-rolled `inm.contains(etag)` became the
  shared comparison.
- [x] **L28** · **DONE** · `If-None-Match: *` on PUT is create-only; **only** the `*` form relaxes the
  mandatory-precondition rule, because a tag list names no version of the resource and admitting it
  would turn one junk header into an unconditional overwrite. PATCH is now conditional like PUT
  (prior-14), placed after the method-applicability checks so a merge-patch on a PNG is still 415.
  DELETE stays unconditional, deliberately. ACL PUT/DELETE became conditional (prior-13) on a
  **stored** per-ACL tag — hashing the ACL cannot work, every authorization in one is a blank node.
- [x] **Conformance** · **DONE** · All four auth suites advertised, SAML only when configured. The RDF
  and lws+json renderings of the storage description now come from **one document** — the RDF one
  used to drop every capability's detail. `Link: rel="type"` accepted as a type source and indexed,
  bounded by refusing the whole LWS namespace and the LDP interaction models rather than a
  hand-written list. POST to a data resource is 405, not 409. A type search requires a type clause.

### Batch N — CORS and cost

- [x] **M7** · **DONE** · `http/CorsFilter`, installed ahead of authentication in both wirings and
  only when `lws.cors.allowed-origins` names something. Preflights are answered by the filter with a
  **fixed** method/header set (a derived one would be the existence oracle `handleOptions` was
  rewritten to close). `Access-Control-Allow-Credentials` is never sent; `/app` and `/callback` are
  excluded; `Origin: null` is refused. `*` is legal but **refused at startup in open mode**, where
  every request is authorized anonymously and `*` would hand the storage to any site a browser
  visits.
- [x] **M23 / M39** · **DONE** · `Authorizer.allowsEverything` lets a caller skip a per-member loop
  when the answer cannot vary by resource — the ordinary deployment, where a 200,000-member listing
  was asking one question 200,000 times. The listing filter moved *inside* the read transaction and
  runs over cheap `ChildRef`s; page metadata comes from a windowed `ResourceRegistry.describe`; a
  container's RDF model is built only when RDF is negotiated. The same shortcut was applied to the
  type index and type search, which had the identical shape. **Deviation:** the filter itself is not
  pushed into the page window, because `totalItems` must reflect the disclosable view and an exact
  count of that needs every member considered.
- [x] **prior-12** · **DONE** · Grants carry `urn:x-lws:accessAssignee` index triples and a check asks
  the store only for grants that could name the requester; the JSON stays authoritative, so the index
  can only ever *remove* candidates. Legacy unindexed grants are admitted unconditionally by the
  query and backfilled at startup. Parsed documents are cached keyed by their own text.
  **Deviation:** no target-prefix index — the assignee filter already bounds the candidate set, and
  `targetCovers` is a prefix match SPARQL would express badly.
- [x] **M25** · **DONE 2026-08-26** · Set alongside the cookie hardening in `JettyLauncher.buildHandler`.

## P3 — Hygiene, docs, and the long tail

### Project scaffolding — **DONE 2026-08-26**

- [x] · **DONE** · `.github/workflows/build.yml`: `mvn -B -ntp verify` on push, PR and weekly (a dependency withdrawn on Monday should not wait for someone to push). Runs the enforcer as well as the tests; uploads surefire reports and the SBOM.
- [x] · **DONE** · Apache 2.0. `LICENSE` is byte-identical to the canonical 11,358-byte text (extracted from a dependency jar and structurally verified rather than retyped), plus `NOTICE`, `<licenses>`/`<inceptionYear>`/`<developers>` in the POM, and a README section. Copyright 2026 Erich Bremer. **Per-file source headers are NOT applied** — ~145 files, a separate call.
- [x] · **DONE** · `SECURITY.md`: private channel, what to include, triage order, an explicit in/out-of-scope list (the four documented-by-design postures are out of scope, but a control that does not do what it says is in), and a closing note that this repo's own review documents describe unfixed findings and gate publication.
- [x] · **DONE** · `.github/dependabot.yml` (weekly, Maven + Actions, with the convergence pins grouped so they land in one PR rather than a series that each fail the enforcer), and a CycloneDX SBOM in an opt-in `-Psbom` profile wired into CI. *(Deviation: OWASP `dependency-check` deliberately omitted — it wants an NVD API key and a database in the hundreds of megabytes, which is an operational commitment rather than a plugin declaration, and Dependabot already covers "this dependency has a known advisory" for a GitHub-hosted repo. Neither plugin is in the local `~/.m2`, so the profile is **unverified offline**.)*
- [x] · **DONE** · `dependencyConvergence` + `requireUpperBoundDeps` + Maven/Java floors, and **it immediately found six real divergences**, not the one predicted: `asm` (9.7.1/9.9.1), `commons-io` (2.20.0/2.21.0) and `error_prone_annotations` (2.36.0/2.41.0/2.43.0) diverging outright, and `bcprov` (1.83 vs shiro-crypto-hash wanting 1.84), `commons-lang3` (3.18.0 vs jena-arq wanting 3.19.0) and `commons-codec` (1.18.0 vs jena-base wanting 1.19.0) pinned by the Spring BOM *below* what a transitive needs. All six pinned in `dependencyManagement` at the highest requested version; Bouncy Castle moved to a `${bouncycastle.version}` property so its three modules cannot drift apart.
- [x] · **DONE** · surefire pinned to 3.5.4; `project.build.outputTimestamp=2026-01-01T00:00:00Z`.
- [x] · **DONE** · `jakarta.json-api` (compile) + `parsson` (runtime), declared directly.
- [x] · **DONE (partly — read this)** · Marked `<optional>true</optional>`, so nothing that depends on lws-server inherits Fuseki. **That does not shrink the fat jar**: Spring Boot packages optional dependencies, because they are still on this project's own compile classpath. Shrinking it needs `<scope>provided</scope>`, which would make `lws.sparql.enabled=true` a `NoClassDefFoundError` on the shipped jar — disabling a documented feature is a product decision, not a build-hygiene one. Left as `optional` with that trade recorded.
- [x] · **DONE** · Replaced by direct `junit-jupiter` **and `mockito-core`** — the finding's "tests use only JUnit Jupiter" was true when written, but Batch C's `AuthenticationFilterTest` mocks the servlet API. Versions still come from the Spring Boot BOM.

### Tests that pin the fixes above — **PARTLY DONE 2026-08-26** (5 of 12; see each item)

- [x] **M42** · **DONE 2026-08-26** · `WacHttpIntegrationTest`, 6 tests over the real stack in WAC mode with a configured owner: only a controller may write an ACL (owner 201 / Bob 403 / anonymous 401, and the refused writes changed nothing); the root ACL cannot be deleted; writing an ACL changes what Bob may GET and Read is not Write; **revocation takes effect on the next request**; an own-ACL outranks an inherited `acl:default` and the container listing hides what Bob may not read; and responses carry `Link …; rel="acl"`.
- [x] · **DONE 2026-08-27 (Batch R)** · `auth/DpopHttpIntegrationTest`, 17 tests over the real stack. Also pins the RFC 9449 §7.1 downgrade defence for **both** `Bearer` and `SAML2` — the latter was the pre-existing critical the P2 adversarial pass found and had no end-to-end test. Original item: **An HTTP-level DPoP class**: valid token+proof → 200; missing nonce → 401 with `DPoP-Nonce` and `error="use_dpop_nonce"`; wrong-path proof → 401; `cnf.jkt` mismatch → 401; the same token as `Bearer` → 401. **M-tests** — no test sends a `DPoP` or `SAML2` header at all today.
- [x] · **DONE** · Already closed by Batch J's H7 work: `EndToEndTest` now asserts **401** for anonymous creation and `WebhookDeliveryTest` mints a subscriber token. Verified rather than re-done.
- [x] · **DONE 2026-08-27 (Batch R)** · `AbstractOperationsConformance` + `OperationsConformanceTest` (open) + `OperationsConformanceOwnerTest` (owner). All 28 methods moved verbatim; 28 pass in each mode. Original item: **Re-run the conformance suite with owners configured** — `OperationsConformanceTest` and eight sibling classes run in open mode, so their 435+ lines assert no authorization outcome (**M47**).
- [x] · **DONE 2026-08-27 (Batch R)** — `withinValidity` had zero executed lines; now covered including both skew-tolerance cases and the fail-closed unparseable timestamp. The `AudienceRestriction` half was already covered and was verified rather than duplicated. **M40** SAML `Conditions` window + `AudienceRestriction` cases (both currently short-circuit in every test).
- [x] · **DONE 2026-08-27 (Batch R)** — 12 tests, including the three `targetCovers` branches and the sibling-with-a-shared-prefix case nothing pinned. **M41** grant `dateTime` expiry, `client` constraint, and the container-prefix branch of `targetCovers`.
- [x] · **DONE 2026-08-27 (Batch R)** — the old case passed without ever running `RSASSAVerifier`; both rejection reasons are now pinned separately. **M44** re-mint the "foreign key" test with `keyID("test-key")` so signature verification actually runs.
- [x] · **DONE 2026-08-27 (Batch R)** — measured first: read-only is 404 (no update endpoint registered) plus 405 "Read-only" on the graph-store path, not the 403/405 the review guessed. Plus a read-write companion and a loopback binding test. **M45** assert the Fuseki read-only rejection is specifically 403/405 with the dataset unchanged, plus a `read-only=false` companion and a `loopback` binding test.
- [x] · **DONE 2026-08-26** · `IrisTest`, 9 tests: traversal slugs (including backslash and percent-encoded forms) cannot introduce a segment; dots-only and separators-only collapse to null; sanitising can *produce* a reserved name (the reason C2 guards the composed path); binary keys are opaque and unique over 500 mints; and `parentPath`/`isWithin`/`toPath` edges, including that `isWithin` is not a prefix match and `toPath` returns null outside the base. **Two of my own assertions were wrong about the real behaviour and were corrected to it** rather than the other way round.
- [x] · **DONE 2026-08-27 (Batch R)** — `FileSystemBinaryStoreTest` (10), `RdfFormatsTest` (20), `Tdb2RdfStoreTest` (5), `LoginPageTest` (12). `RdfFormatsTest` found two real bugs, both fixed. Original item: Add tests for the four wholly untested classes: `FileSystemBinaryStore`, `RdfFormats`, `Tdb2RdfStore`, `LoginPage`.
- [x] **M46** · **DONE 2026-08-26** · The mutating test cleans up in a `finally`, so a failure there no longer also fails the exact-set assertion with a second, misleading red; and the class declares `@TestMethodOrder` with explicit `@Order` rather than relying on JUnit's unspecified default.
- [x] · **DONE 2026-08-26 — but not with `@TempDir`** · All 17 sites now go through a new `TestDirs`. **`@TempDir` does not work here and the attempt is worth recording:** TDB2 memory-maps its files, Windows refuses to delete a mapped file while the mapping exists, and Java offers no way to force an unmap — so JUnit's cleanup throws and fails the very class it is tidying up after. Converting the suite turned 14 green classes into 14 `Failed to close extension context` errors. `TestDirs` instead moves the deletion to **the next run**, when the previous JVM and its mappings are gone: each run sweeps what earlier ones left, creates its own, and tries its own on exit. **Measured**: a full run followed by another left the directory count unchanged (310 → 310), so the accumulation is bounded at roughly one run instead of growing without limit.

### Docs — **DONE 2026-08-26**

- [x] · **DONE** · README now says JDK 25 and why (class-file major 69).
- [x] · **DONE** · `tls/` and `tools/` added, the `http/` line now lists every servlet, and both config keys are in the table (plus the three new `lws.webhook.*` pool keys from Batch J).
- [x] · **DONE** · Both were already corrected when H1 and the 401 `Link` landed in Batches C and A; verified rather than re-done.
- [x] **L58** · **DONE 2026-08-26** · Took the "better" option: `LwsServletConfig` logs a WARN naming the port it is actually serving plaintext on and pointing at the two real ways to get TLS. An operator who set `lws.tls.enabled=true` and saw the server come up had every reason to believe it was serving HTTPS.
- [x] · **DONE** · Already updated when H2 landed in Batch C; verified.

### Long tail

The remaining ~46 low findings and 19 nits in `REVIEW.md` are individually cheap and individually minor. Worth a dedicated cleanup pass once P2 is done. **The twelve "most likely to bite" listed here are DONE (2026-08-26)** except one, noted below:

- [x] · **DONE** · `requireSigningKey` cross-checks header `alg` against the JWK's `alg`, `use` and `key_ops`, refuses an OKP key whose curve is not Ed25519 (X25519 is key agreement and its `x` is also 32 bytes, so nothing downstream noticed), and refuses EdDSA against a non-OKP key.
- [x] · **DONE** · Landed with H15 in Batch H; verified.
- [x] · **PARTLY DONE — read this** · **OPTIONS is now authorized**: it took no principal at all, so `Allow`/`Accept-Post`/`Accept-Patch` were computed from the stored resource and returned to anyone — an existence oracle with the resource's type attached. **The 404-before-403 reordering was NOT done**, and deliberately: Batch D already tried and rejected the naive hoist (see H16's "Fixed:" section — `OwnerAuthorizer` denies any IRI with no registry entry, so authorizing first turns seven existing `404` assertions into `401`). Closing the oracle properly means masking `403` as `404` for readers without Read — **DONE 2026-08-27 (Batch Q)**, along with two leaks the design missed: OPTIONS discriminated in the opposite direction, and anonymous kept the whole oracle because an absent resource never reaches the authorization check. See `REVIEW.md`'s Batch Q section, including what it deliberately does not close under WAC.
- [x] · **DONE** · Verified already correct: the servlet's catch answers a fixed "Internal server error" and logs the exception, rather than echoing its message.
- [x] · **DONE** · A trailing `catch (RuntimeException)` maps the structurally-invalid-patch cases (`ClassCastException`, `NullPointerException`, `IllegalArgumentException`, depending on the shape) to 400.
- [x] · **DONE** · All three. The redirect target now comes from the configured base URI rather than the request's `Host` (reflecting it made this an open redirect any client could aim anywhere), the status is 308 so a redirected POST stays a POST, and the response carries HSTS. `AcmeSupportTest` gained a raw-socket request with a spoofed `Host` — the JDK HttpClient refuses to set that header — asserting the attacker's host does not reach `Location`.
- [x] · **DONE** · Fixed in Batch F alongside M9; verified.
- [x] · **DONE** · A negative answer is now re-counted at most every 30s. Being wrong in the `false` direction silently disables *all* grant authorization and nothing surfaces it; being wrong in the `true` direction just costs an evaluation that finds nothing, which is why only the negative needs a recheck.
- [x] · **DONE** · A failed incremental update drops the whole index (`built = false`) and logs, so the next read rebuilds from the store. The expensive always-correct answer beats a cheap permanently-wrong one.
- [x] · **DONE** · The alias is removed rather than repointed: N3 is a superset of Turtle, not an alias for anything this server implements, so a genuine N3 document failed to parse while an N-Triples one was accepted under a media type the server does not support. Absent from the table it is an honest 415.
- [x] · **DONE** · `lws.properties` unanchored (it is on the shipped jar's classpath from `src/main/resources`), the smoke-test artefacts anchored to the root. **Both directions verified with `git check-ignore`**: the dangerous path is now ignored, and a `src/test/resources/note.ttl` fixture is not.
- [x] · **DONE** · Each step runs through `closeQuietly`. The one most likely to throw — the optional SPARQL server — sat in front of the two that matter most, and a TDB2 store left open holds its lock file, which turns "shutdown logged a stack trace" into "the next start fails".

---

## The low/nit tail — the 53 still open

An inventory was taken on 2026-08-27 against the *current* code rather than the review text: of
the ~65 low findings and 19 nits, **47 were already closed** as a side effect of the H/M work, 3
do not apply, and 63 were genuinely open. Batch S took ten (see `REVIEW.md`). These are the rest,
in the inventory's order. Each was verified as still open at that date.

- **AUTH #1** — SsiCidValidator: accepts any `verificationMethod` carrying a matching kid, ignoring the `authentication` verification relationship.  
  `src/main/java/com/ebremer/lws/server/auth/SsiCidValidator.java:170`
- **AUTH #3** — LwsOpenIdValidator: seeds the signature-algorithm allow-list from the token's own header, making the key-selector check tautological.  
  `src/main/java/com/ebremer/lws/server/auth/LwsOpenIdValidator.java:128`
- **AUTH #4** — LwsOpenIdValidator: cannot verify EdDSA-signed ID tokens even though the codebase has an Ed25519 verifier.  
  `src/main/java/com/ebremer/lws/server/auth/LwsOpenIdValidator.java:127`
- **AUTH #7** — SamlValidator: loads trust anchors as bare public keys, discarding certificate validity dates.  
  `src/main/java/com/ebremer/lws/server/auth/SamlValidator.java:110`
- **AUTH #10a** — AuthenticationFilter: returns `error="invalid_token"` for DPoP proof failures instead of RFC 9449's `invalid_dpop_proof`.  
  `src/main/java/com/ebremer/lws/server/auth/AuthenticationFilter.java:242`
- **AUTH #11** — AuthenticationFilter: malformed and unknown-scheme `Authorization` headers are downgraded to anonymous instead of 401.  
  `src/main/java/com/ebremer/lws/server/auth/AuthenticationFilter.java:123`
- **AUTH #14** — AuthenticationFilter only ever emits `DPoP-Nonce` on the 401 challenge, costing a wasted round-trip every 5 minutes.  
  `src/main/java/com/ebremer/lws/server/auth/AuthenticationFilter.java:231`
- **AUTH #15** — WacAclService never invalidates the agentGroup cache on local group-document edits, delaying revocation by up to the cache TTL.  
  `src/main/java/com/ebremer/lws/server/auth/WacAclService.java:267`
- **AUTH #16** — WacAclService accepts any subject with `acl:accessTo`/`acl:mode` as an authorization without requiring `rdf:type acl:Authorization`.  
  `src/main/java/com/ebremer/lws/server/auth/WacAclService.java:100`
- **CORE/HTTP #3** — `dateTime` constraints silently never match unless the value is a UTC/offset instant, with no issuance-time diagnostic.  
  `src/main/java/com/ebremer/lws/server/core/AccessService.java:850`
- **CORE/HTTP #4** — the class javadoc claims purpose/mediaType/type constraints make a grant inactive; the code implements all three as satisfiable.  
  `src/main/java/com/ebremer/lws/server/core/AccessService.java:43`
- **CORE/HTTP #5a** — ResourceService resolves existence before authorization, giving unauthenticated clients an existence oracle (404 vs 403).  
  `src/main/java/com/ebremer/lws/server/core/ResourceService.java:185`
- **CORE/HTTP #6** — recursive delete uses unbounded recursion and O(N) queries inside the exclusive write transaction.  
  `src/main/java/com/ebremer/lws/server/core/ResourceService.java:794`
- **CORE/HTTP #7** — quota accounts only for non-RDF bytes and re-sums every `byteSize` triple on each binary write inside the write transaction.  
  `src/main/java/com/ebremer/lws/server/core/ResourceService.java:806`
- **CORE/HTTP #8** — the charset parameter is stripped from the stored Content-Type and never restored (mojibake on read).  
  `src/main/java/com/ebremer/lws/server/core/ResourceService.java:923`
- **CORE/HTTP #12** — weak comparison is used for `If-Match` (and it shares the tag parser with `If-None-Match`).  
  `src/main/java/com/ebremer/lws/server/core/IfMatch.java:123`
- **CORE/HTTP #15** — raw `IOException` messages — including filesystem paths — are echoed into problem+json detail on 500s.  
  `src/main/java/com/ebremer/lws/server/core/ResourceService.java:581`
- **CORE/HTTP #17** — `If-Range` is ignored.  
  `src/main/java/com/ebremer/lws/server/http/LwsResourceServlet.java:342`
- **L35** — NotificationEmitter drops clientId when reconstructing the subscriber principal, so client-constrained grants never apply at delivery  
  `src/main/java/com/ebremer/lws/server/notifications/NotificationEmitter.java:104`
- **L36a** — SubscriptionService opens a write transaction for every delivery, including successful no-ops  
  `src/main/java/com/ebremer/lws/server/notifications/SubscriptionService.java:327`
- **L36b** — recordDelivery's read-modify-write is non-atomic on the REMOTE backend  
  `src/main/java/com/ebremer/lws/server/notifications/SubscriptionService.java:327 (with RemoteSparqlRdfStore.java:46)`
- **L38** — SubscriptionService never reaps permanently deactivated subscriptions  
  `src/main/java/com/ebremer/lws/server/notifications/SubscriptionService.java:209`
- **L40** — WebhookKeys has no key rotation (one JWK, one-hour cache, no overlap)  
  `src/main/java/com/ebremer/lws/server/notifications/WebhookKeys.java:118 (and JwksServlet.java:39)`
- **L41a** — WebhookDispatcher.close() does not drain the pool  
  `src/main/java/com/ebremer/lws/server/notifications/WebhookDispatcher.java:263`
- **L41b** — WebhookDispatcher.close() does not close the HttpClient  
  `src/main/java/com/ebremer/lws/server/notifications/WebhookDispatcher.java:263`
- **L41c** — WebhookDispatcher.close() races rdfStore.close()  
  `src/main/java/com/ebremer/lws/server/notifications/WebhookDispatcher.java:263 (with LwsComponents.java:314)`
- **L43a** — FileSystemBinaryStore never fsyncs, so durably committed metadata can point at unflushed bytes after power loss  
  `src/main/java/com/ebremer/lws/server/storage/FileSystemBinaryStore.java:62`
- **L43b** — unguarded deleteIfExists in finally can mask the primary IOException  
  `src/main/java/com/ebremer/lws/server/storage/FileSystemBinaryStore.java:70`
- **L43c** — crash-leftover .lws-*.tmp files are never reaped or counted against quota  
  `src/main/java/com/ebremer/lws/server/storage/FileSystemBinaryStore.java:57`
- **L45a** — validateTls() checks neither the base-URI scheme nor tlsPort != tlsHttpPort (scheme half)  
  `src/main/java/com/ebremer/lws/server/LwsConfiguration.java:545`
- **L45b** — validateTls() does not check tlsPort != tlsHttpPort  
  `src/main/java/com/ebremer/lws/server/LwsConfiguration.java:545 (fields set at :312-313)`
- **L45c** — a base URI without an explicit port silently listens on 8080, and its port is never range-checked, unlike every other port key  
  `src/main/java/com/ebremer/lws/server/LwsConfiguration.java:171`
- **L45e** — acme.renew-before-days has no upper bound, so a lead time >= the certificate lifetime re-orders every 12h until the CA rate-limits  
  `src/main/java/com/ebremer/lws/server/LwsConfiguration.java:322`
- **L46a** — AcmeCertificateManager reuses a cached certificate without checking it covers lws.tls.acme.domains  
  `src/main/java/com/ebremer/lws/server/tls/AcmeCertificateManager.java:108`
- **L46b** — AcmeCertificateManager never rotates the domain private key across renewals  
  `src/main/java/com/ebremer/lws/server/tls/AcmeCertificateManager.java:119`
- **Nit/L46g** — DidKeyTool takes the Ed25519 private seed only via argv (visible in ps / shell history)  
  `src/main/java/com/ebremer/lws/server/tools/DidKeyTool.java:97`
- **L46h** — DidKeyTool's fixed-pair argument loop silently discards options after a stray flag  
  `src/main/java/com/ebremer/lws/server/tools/DidKeyTool.java:97`
- **L49** — jena-fuseki-main is compile-scope for a default-disabled feature; the fat jar carries 159 third-party jars / 63.5 MB  
  `pom.xml:200`
- **L52d** — no CONTRIBUTING  
  ` (no CONTRIBUTING.md)`
- **L52f** — no dependency-vulnerability scan  
  `.github/workflows/build.yml`
- **L55** — REVIEW-lws-server.md is tracked and pushed, publishing eight still-unfixed vulnerabilities with file:line exploit pointers, with no SECURITY.md disclo  
  `REVIEW-lws-server.md (git ls-files: tracked)`
- **L58** — eleven classes bind-close-rebind an ephemeral port, leaving a TOCTOU window  
  `src/test/java/com/ebremer/lws/server/AccessGrantsTest.java:412 (and 15 sibling classes)`
- **L59** — no test exercises the REMOTE backend or the Spring Boot entry point  
  `src/main/java/com/ebremer/lws/server/rdf/RemoteSparqlRdfStore.java (no corresponding test)`
- **L60** — dueForRenewal() is an untested pure predicate although AcmeSupportTest already builds the 90-day certificate it needs  
  `src/test/java/com/ebremer/lws/server/tls/AcmeSupportTest.java`
- **L61** — LoginPage, the WebID-impersonation dev-login form, has no test; the suite turns dev-login on and bypasses the page by calling signIn directly  
  `src/test/java/com/ebremer/lws/server/ui/LwsUiTest.java`
- **Nit 1** — DidKey accepts uncompressed and hybrid EC point encodings, so one key has several did:key spellings that compare unequal in ACLs  
  `src/main/java/com/ebremer/lws/server/auth/DidKey.java:54`
- **Nit 2** — AuthenticationFilter overloads a null return with two opposite meanings, disambiguated only by response.isCommitted()  
  `src/main/java/com/ebremer/lws/server/auth/AuthenticationFilter.java:115 (caller at :79)`
- **Nit 6b** — RdfFormats has a dead tie-break in negotiate()  
  `src/main/java/com/ebremer/lws/server/rdf/RdfFormats.java (negotiate, `q == bestQ && rank < bestRank`)`
- **Nit 6c** — RdfFormats has a dead wildcard branch in negotiate()  
  `src/main/java/com/ebremer/lws/server/rdf/RdfFormats.java (negotiate, the `if (best == null)` loop)`
- **Nit 7** — ActivityKind.as2Type() is dead code, re-derived by string capitalization in NotificationEmitter  
  `src/main/java/com/ebremer/lws/server/core/ActivityKind.java:24`
- **Nit 8** — JettyLauncher instantiates SubscriptionServlet twice where Spring registers one  
  `src/main/java/com/ebremer/lws/server/JettyLauncher.java:305,307`
- **Nit 9** — LwsServletConfig builds throwaway pass-through filters for disabled pac4j registrations  
  `src/main/java/com/ebremer/lws/server/LwsServletConfig.java:229 and :246`
- **Nit 10** — AccessGrantsTest.headers takes a contentType it never reads and passes it through a tautological ternary  
  `src/test/java/com/ebremer/lws/server/AccessGrantsTest.java:372 (ternary at :369)`