---
title: Getting Started
nav_order: 2
---

# Getting Started
{: .no_toc }

1. TOC
{:toc}

## Prerequisites

- **JDK 25.** The build sets `maven.compiler.release=25`, so it emits class-file version 69 and will
  not load on an earlier JDK.
- **Maven 3.9+**.

## Build

```bash
mvn -DskipTests package
```

This produces an executable `target/lws-server.jar`.

## Run

The server **refuses to start with no `lws.owners`**: an empty owner list is *open mode*, where every
read, write and control decision is permitted for every client, anonymous ones included. For a quick
local try-out, ask for open mode explicitly:

```bash
java -Dlws.dev.open=true -jar target/lws-server.jar
```

For anything else, [mint an owner](#the-first-owner) first and set `lws.owners`.

### Spring Boot (default)

```bash
java -jar target/lws-server.jar
# or
mvn spring-boot:run
```

### Bare Eclipse Jetty (no Spring)

The same servlets and filters run on a hand-built Jetty server with no Spring on the classpath — the
intended future deployment target, and the only path that can [terminate TLS itself](deployment.md).

```bash
mvn dependency:build-classpath -Dmdep.outputFile=target/cp.txt
java -cp "target/classes:$(cat target/cp.txt)" com.ebremer.lws.server.JettyLauncher
```

The server listens on the port in `lws.base-uri` (default `http://localhost:8080`), or on
`lws.listen-port` when that is set. Configuration comes from `./lws.properties` or `-Dlws.*` — see
[Configuration](configuration.md).

## First requests

In open mode (`lws.dev.open=true`) no credential is needed:

```bash
# the storage URI answers with the storage description (application/lws+cid)
curl http://localhost:8080/

# create an RDF resource in the root container
curl -i -X POST -H 'Content-Type: text/turtle' -H 'Slug: greeting' \
     --data '<#it> <http://schema.org/name> "Hello LWS" .' http://localhost:8080/

# read it back as JSON-LD
curl -H 'Accept: application/ld+json' http://localhost:8080/greeting

# list the root container instead of describing the storage
curl -H 'Accept: application/lws+json' http://localhost:8080/

# create a container, add a resource, then patch it with SPARQL Update
curl -X PUT -H 'Link: <http://www.w3.org/ns/ldp#Container>; rel="type"' http://localhost:8080/box/
curl -X PUT -H 'Content-Type: text/turtle' --data '<#x> <http://schema.org/n> 1 .' http://localhost:8080/box/x
curl -X PATCH -H 'Content-Type: application/sparql-update' \
     --data 'INSERT DATA { <http://localhost:8080/box/x#x> <http://schema.org/age> 42 }' http://localhost:8080/box/x
```

The storage description is also served at `/.lws/storage-description`, and every `GET` and `HEAD`
of a resource carries `Link: <storage URI>; rel="https://www.w3.org/ns/lws#storage"`.
See the [HTTP API](http-api.md) for the full surface.

## The first owner

`lws.owners` holds WebIDs/DIDs, but you need a *credential* for one before you can act as that owner.
A `did:key` subject of the
[self-signed Controlled Identifier](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/) suite
needs no identity provider — its DID document is derived from the identifier itself — so a bundled
helper can mint the very first owner offline:

```bash
# from the packaged fat jar
java -cp target/lws-server.jar -Dloader.main=com.ebremer.lws.server.tools.DidKeyTool \
     org.springframework.boot.loader.launch.PropertiesLauncher --audience http://localhost:8080

# or, from a source checkout
mvn -q exec:java -Dexec.mainClass=com.ebremer.lws.server.tools.DidKeyTool \
    -Dexec.args="--audience http://localhost:8080"
```

It prints:

1. a `did:key:…` to put in `lws.owners`,
2. a private-key **seed** to keep secret (pass it back with `--key <seed>` to mint new credentials for
   the same identity), and
3. a **credential** — a self-issued JWT whose `kid` names the DID's verification method.

Options: `--key <seed>`, `--ttl <seconds>` (credential lifetime, default 3600; the server caps
self-signed credentials at `lws.token.max-lifetime-seconds`) and `--audience <aud>`.

{: .warning }
> **Always pass `--audience` with your `lws.base-uri`.** The server requires an `aud` claim by default
> (`lws.audience.require=true`), and the token endpoint only accepts a credential whose audience names
> its authorization server — whose issuer is `lws.base-uri`. A credential minted without `--audience`
> is refused with `invalid_request`.

Put the DID in `lws.owners`, restart without `lws.dev.open`, and exchange the credential for an
access token at the storage's authorization server:

```bash
curl -s http://localhost:8080/.lws/token \
     -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
     --data-urlencode resource=http://localhost:8080/ \
     --data-urlencode subject_token="$CREDENTIAL" \
     -d subject_token_type=urn:ietf:params:oauth:token-type:jwt
# {"access_token":"eyJ...","issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
#  "token_type":"Bearer","expires_in":300}

curl -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Accept: application/lws+json' http://localhost:8080/
```

Presenting the credential itself as `Authorization: Bearer <credential>` also works while
`lws.oauth.accept-authentication-credentials=true` (the default). See
[Authentication](authentication.md) for both routes.

## Next steps

- [Configuration](configuration.md) — tune storage, auth, quotas, TLS.
- [Authentication](authentication.md) — access tokens, the credential suites and DPoP.
- [Authorization](authorization.md) — owner mode vs Web Access Control, and access grants.
- [Deployment & TLS](deployment.md) — production behind a proxy (at the root or under a path), or with built-in Let's Encrypt.
