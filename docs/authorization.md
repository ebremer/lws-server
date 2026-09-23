---
title: Authorization
nav_order: 8
---

# Authorization
{: .no_toc }

1. TOC
{:toc}

Every access decision goes through a pluggable `Authorizer`. Two models are available via
`lws.access-control`, and **access grants** layer on top of whichever is chosen.

## Owner mode (default)

`lws.access-control=OWNER` is single-tenant: the identities in `lws.owners` have full control; others
get public-read when `lws.public-read=true`. With **no owners configured the storage is in open
mode** (all reads and writes permitted) — fine for local development, not for production.

## Web Access Control (WAC)

Set `lws.access-control=wac` for multi-user authorization via
[Web Access Control](https://solidproject.org/TR/wac). Each resource may have an ACL resource
(`<resource>.acl`, or `<container>/.acl`), discoverable via the `Link: rel="acl"` header. ACLs are
RDF documents containing `acl:Authorization` rules:

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
  subject to the [SSRF guard](security.md)) and checking `vcard:hasMember`, cached briefly.
- **`acl:origin`** restricts a rule to a browser/app `Origin` (note: client-declared, not attested).
- **Resolution**: a resource's own ACL (`acl:accessTo`) wins; otherwise the nearest ancestor
  container's ACL applies through `acl:default` (inheritance), up to the root. The nearest ACL fully
  overrides ancestors — there is **no super-owner**, so include yourself when delegating a subtree.
- **Bootstrap**: the root ACL is created at startup from `lws.owners` (Read/Write/Control + public
  Read if `lws.public-read`); with no owners the root is opened to the public (development).
- Editing an ACL requires `acl:Control` on its target (ACLs are not themselves access-controlled,
  avoiding infinite regress).

To onboard a user, point them at their OIDC issuer (their WebID document must advertise an
`lws:OpenIdProvider` service for that issuer — see [Authentication](authentication.md)) and grant
their WebID the modes they need in the relevant ACLs.

## Access Requests & Grants

The storage description advertises an `AccessRequestService` and an `AccessGrantService` (each with a
`serviceEndpoint` and a `conformsTo` access profile). Both are LWS containers served as
`application/lws+json`.

- **Request** — any authenticated agent `POST`s an `AccessRequest` to `/.lws/access-requests`
  (`201` + `Location`); the requester or a controller may `GET`/list/`DELETE` it.
- **Grant** — a storage controller `POST`s an `AccessGrant` to `/.lws/access-grants`; deleting it
  revokes the grant.

```json
POST /.lws/access-grants    Content-Type: application/lws+json    (storage controller)
{
  "@context": "https://www.w3.org/ns/lws/v1",
  "type": ["AccessGrant"],
  "storage": "http://localhost:8080/",
  "access": [
    { "type": ["AccessPolicy"], "action": ["read"],
      "assignee": "https://bob.example/me",
      "target": { "type": "StorageResource", "value": ["http://localhost:8080/doc"] } }
  ]
}
```

### How grants are enforced

A grant is enforced by a **grant-aware authorizer layered over the base model** (owner or WAC): an
operation is permitted if the base permits it *or* an active grant authorizes it. So an assignee can
act on the targets **without any ACL edit**, and deleting the grant withdraws the access immediately.

- **Actions** map to operations: `read` → GET/HEAD, `modify` → PUT/PATCH, `create` → POST,
  `delete` → DELETE.
- **Assignee** may be `http://xmlns.com/foaf/0.1/Agent` for public access.
- **Target** matches a resource exactly, or — for a container value — its whole subtree.
- **Constraints** are evaluated fail-closed: `dateTime`, `client`, `mediaType`, `type` and `purpose`
  are honoured (`mediaType`/`type` from the target's metadata; `purpose` from a client-declared
  `LWS-Purpose` request header).
- Grants **never** confer `Control`.

On creation the server delivers a signed `lws:Notification` (an Activity Streams 2.0 `Create` about
the new document, RFC 9421-signed like a webhook) to the relevant inboxes: the document's own `inbox`,
the configured controller inbox for a new request, and — for a grant that references its request via a
`request` link — the associated request's inbox. See [Notifications](notifications.md).

> `acl:origin` and the access-grant `purpose` are **client-declared**, not cryptographically attested
> — as is the nature of origin/purpose policy.
