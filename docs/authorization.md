---
title: Authorization
nav_order: 8
---

# Authorization
{: .no_toc }

1. TOC
{:toc}

Every access decision goes through a pluggable `Authorizer`, consulted by the service layer so that
the HTTP API, the management UI and the search services enforce exactly the same rules. Two models
are available via `lws.access-control`, and [access grants](access-requests.md) layer on top of
whichever is chosen. Who the caller *is* comes from [Authentication](authentication.md).

## Owner mode (default)

`lws.access-control=OWNER` is single-tenant: the identities in `lws.owners` (WebIDs or DIDs) have
full control. Everyone else can read the storage only when `lws.public-read=true`, which is
**storage-wide** and defaults to `false`. To open a single resource or subtree to the world, issue an
[access grant](access-requests.md) with `assignee` `http://xmlns.com/foaf/0.1/Agent` instead;
deleting it closes the access again on the next request.

> **The server refuses to start with no `lws.owners`.** An empty owner list is *open mode* — every
> read, write and control decision permitted for every client, anonymous included. It is still
> available for development, but has to be asked for with `lws.dev.open=true`. Open mode has no
> storage *controller*, so access grants cannot be issued in it at all.
{: .warning }

## Web Access Control (WAC)

Set `lws.access-control=wac` for multi-user authorization via
[Web Access Control](https://solidproject.org/TR/wac). Each resource may have an ACL resource
(`<resource>.acl`, or `<container>/.acl`), discoverable via the `Link: rel="acl"` header. That is the
address the ACL is read and written at; the graph itself is kept in the server-internal
`urn:x-lws:acl:` namespace, so no resource a client creates can ever be its own governing ACL. ACLs
are RDF documents containing `acl:Authorization` rules:

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .

# Bob may read & write everything under /shared/
<#bob> a acl:Authorization ;
    acl:accessTo <http://localhost:8080/shared/> ;
    acl:default  <http://localhost:8080/shared/> ;   # inherited by contained resources
    acl:agent    <https://bob.example/profile#me> ;
    acl:mode     acl:Read, acl:Write .

# Any signed-in agent may read it; the public may not
<#members> a acl:Authorization ;
    acl:accessTo   <http://localhost:8080/shared/> ;
    acl:agentClass acl:AuthenticatedAgent ;
    acl:mode       acl:Read .
```

### Rules

- **Modes** map to operations: `acl:Read` → GET/HEAD; `acl:Append` → POST/PUT-create; `acl:Write` →
  PUT-overwrite/PATCH/DELETE (Write implies Append); `acl:Control` → read/write the resource's ACL.
- **Agents**: `acl:agent <webid>`; `acl:agentClass foaf:Agent` (everyone, incl. anonymous) or
  `acl:AuthenticatedAgent` (any signed-in agent); or `acl:agentGroup <group>` — membership is resolved
  by dereferencing the group document (from the local store, or over HTTP for an external group,
  subject to the [SSRF guard](security.md#ssrf-guards)) and checking `vcard:hasMember`.
- **Group resolution** is cached for `lws.wac.group-cache-seconds` (default 300). An external group
  document is fetched *before* the storage transaction that needs the decision opens, never inside
  it, so a slow host cannot stall writes. A group that cannot be resolved simply does not match (its
  authorization is skipped; the others still apply), is not remembered as empty, and is not retried
  for `lws.wac.group-failure-cache-seconds` (default 30). One decision dereferences at most
  `lws.wac.max-group-fetches-per-decision` (default 8) documents.
- **`acl:origin`** restricts a rule to a browser/app `Origin` (client-declared, not attested). A
  browser application needs *both* its origin in `lws.cors.allowed-origins` (so the browser lets it
  read responses) and, if the ACL restricts by origin, a matching `acl:origin`.
- **Resolution**: a resource's own ACL (`acl:accessTo`) wins; otherwise the nearest ancestor
  container's ACL applies through `acl:default` (inheritance), up to the root. The nearest ACL fully
  overrides ancestors — there is **no super-owner**, so include yourself when delegating a subtree.
- **Bootstrap**: the root ACL is created at startup from `lws.owners` (Read/Write/Control, plus
  public Read if `lws.public-read`). With no owners — which requires `lws.dev.open=true` — the root is
  opened to the public instead; that development ACL is marked as such and is **rebuilt** from
  `lws.owners` the first time the server starts with owners configured. A root ACL you wrote yourself
  carries no marker and is never rebuilt (the server warns if it grants everyone `acl:Control`).
- Editing an ACL requires `acl:Control` on its target (ACLs are not themselves access-controlled,
  avoiding infinite regress).

To onboard a user, point them at their OIDC issuer — their WebID document must link that WebID (the
exact IRI the token's `sub` carries) to an `lws:OpenIdProvider` service for that issuer, see
[Authentication](authentication.md) — and grant their WebID the modes they need in the relevant ACLs.
Self-sovereign users can instead authenticate with a controlled identifier (`did:key`, `did:web` or
an HTTPS CID document) and be named by that identifier.

## What callers see when they may not

- An **anonymous** client that lacks access gets `401` with the `as_uri`/`realm` challenge, so it can
  discover how to authenticate.
- An **authenticated** principal without Read gets `404` for a resource that exists, the same as for
  one that does not, and the `Allow` header on `OPTIONS` and `405` stops reporting its type —
  `lws.mask-forbidden-as-not-found` (default `true`). Set it to `false` to answer `403` instead. A
  principal who may read but not write still gets `403` for the write.
- **Container listings** are filtered per member by read authorization: `items` and `totalItems`
  reflect only the resources the client may read, so a listing is client-specific. The
  [type index and type search](search-type-index.md) apply the same per-request check.

> Under WAC, the anonymous `401`/`404` split can still reveal *where* ACLs sit; no status-code
> masking can hide that.
{: .note }

## Access Requests & Grants

Access requests and grants — the LWS way for an agent to ask for access and for a controller to give
it without editing an ACL — have [their own page](access-requests.md). In short: a grant-aware
authorizer is layered over the base model, so an operation is permitted if the base model permits it
*or* an active grant authorizes it, and deleting the grant withdraws the access immediately. Grants
never confer `Control`.
