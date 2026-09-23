---
title: Access Requests & Grants
nav_order: 8.5
---

# Access Requests & Grants
{: .no_toc }

1. TOC
{:toc}

An agent asks a storage for access with an **access request**; a storage controller gives it with an
**access grant**. A grant authorizes its assignee directly — no ACL edit — and deleting it takes the
access away again on the next request. Both follow lws10-core's access requests and its access
profile. The services are on by default (`lws.access-requests.enabled`).

## Discovery and endpoints

The [storage description](http-api.md) advertises an `AccessRequestService` and an
`AccessGrantService`, each with a `serviceEndpoint` and `conformsTo` the LWS access profile. Both
endpoints are **LWS containers** served as `application/lws+json`:

| Endpoint | `POST` (collection) | `GET` / `HEAD` | `DELETE` (entry) |
|---|---|---|---|
| `/.lws/access-requests` | any authenticated agent submits a request | the requester sees their own; a controller sees all | the requester or a controller |
| `/.lws/access-grants` | a storage controller issues a grant | an assignee sees grants naming them; a controller sees all | the issuer or a controller (revocation) |

The paths sit under `lws.system-prefix` (default `/.lws`). A `POST` answers `201` with `Location`
(the server assigns the id). Listings are container representations, paginated at
`lws.container.page-size` like any other container, whose members are data resources typed
`["DataResource", "AccessRequest"]` or `["DataResource", "AccessGrant"]` with `format`
`application/lws+json`. Every read carries the storage `Link` header.

A **storage controller** is an agent with `Control` over the storage root: an owner in owner mode,
an agent granted `acl:Control` on the root ACL under WAC. A storage in open mode (no `lws.owners`)
has no controller, so grants cannot be issued there at all.

## Issuing a grant

```json
POST /.lws/access-grants            Content-Type: application/lws+json   (storage controller)
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

The document is validated at creation:

- `storage` is required and must be this storage (a trailing `/` is supplied if missing);
- `access` is a non-empty array of `AccessPolicy` entries, each with a non-empty `action` array
  (`read`, `modify`, `create`, `delete`) and an `assignee` URI;
- a `target` is **required** (the profile makes it optional, but a grant without one would authorize
  nothing or everything), every `target.value` must be inside this storage, and an unknown matcher
  `type` is refused;
- an `inbox`, if given, must be an acceptable delivery target (the same policy as
  [webhooks](notifications.md)).

An access request has the same shape with `type` `["AccessRequest"]`.

## How grants are enforced

A grant-aware authorizer (`GrantAuthorizer`) is layered over the base model, [owner or
WAC](authorization.md): an operation is permitted if the base permits it *or* an active grant
authorizes it.

- **Actions** map to operations: `read` → GET/HEAD, `modify` → PUT/PATCH, `create` → POST,
  `delete` → DELETE. Grants **never** confer `Control`.
- **Assignee** is the principal's identifier, or `http://xmlns.com/foaf/0.1/Agent` for public
  access — the way to open one resource or subtree when `lws.public-read` is off.
- **Target**: each `value` matches a resource exactly or, for a container, its whole subtree. The
  matcher `type` narrows that: `StorageResource` (the default) matches any resource, `DataResource`
  and `Container` only their own kind.
- **Constraints** (`constraint`: an array of `{leftOperand, operator, rightOperand}`) must all hold,
  and are evaluated **fail-closed** — an operand or operator the server does not understand makes
  the policy authorize nothing:

  | `leftOperand` | Operators | Compared with |
  |---|---|---|
  | `dateTime` | `gteq`, `lteq` | the current time |
  | `client` | `eq`, `isAnyOf` | the credential's `client_id` |
  | `format` | `eq`, `isAnyOf` | the target's media type (`mediaType`, the pre-August-2026 name, is still read) |
  | `type` | `eq`, `isAnyOf` | the target's types, including those its `Link: rel="type"` headers declare |
  | `purpose` | `eq`, `isAnyOf` | the purposes the client declares in an `LWS-Purpose` request header |

A grant carries only the authority of the agent who issued it, and that authority is **re-checked on
every evaluation**: remove the issuer from `lws.owners`, or revoke its `acl:Control` on the root, and
every grant it made stops authorizing on the next request, with no restart and nothing to clean up.
An owner rotation is therefore also a grant revocation — re-issue anything you meant to keep.

As lws10-core's privacy considerations advise, a grant with a `client` constraint is not shown to its
assignee through a different client.

> `acl:origin` and the grant `purpose` are **client-declared**, not cryptographically attested — as
> is the nature of origin/purpose policy. Treat them as advisory scoping. See [Security](security.md).
{: .note }

## Notifications

On creation the server delivers a signed notification — a `Create` activity whose `object` is the
new document, typed `["DataResource", "AccessGrant"]` or `AccessRequest`, RFC 9421-signed like a
webhook — to the relevant inboxes:

- the document's own `inbox`;
- for a new request, the controller inbox `lws.access-requests.controller-inbox`, if set;
- for a grant that references its request through a `request` link, that request's `inbox`.

See [Notifications](notifications.md) for the envelope and signatures.

## Auditing

A grant appears in no owner list and no ACL, so the server logs at startup how many grants are
stored and how many are inert because their issuer no longer controls the storage. Review them at
`/.lws/access-grants` as a controller.
