---
title: Development
nav_order: 15
---

# Development
{: .no_toc }

1. TOC
{:toc}

## Build & test

```bash
mvn package        # compile, run the test suite, build target/lws-server.jar
mvn -DskipTests package
mvn test           # tests only
```

Requires JDK 21+ (built and tested on JDK 25).

## Project layout

The codebase is intentionally framework-light — see [Architecture](architecture.md). Spring Boot is
only a bootstrapper; the whole object graph is wired by the annotation-free `LwsComponents`, and the
bare-Jetty `JettyLauncher` runs the identical servlets/filters with no Spring on the classpath.

**Migrating off Spring** is: delete `LwsServer` and `LwsServletConfig`, and ship `JettyLauncher`. The
bare launcher is also the deployment that can [terminate TLS itself](deployment.md).

## Test coverage

The suite mixes fast unit tests with end-to-end tests that boot the real stack over HTTP.

| Area | Tests |
|---|---|
| Core operations & processes | `OperationsConformanceTest` — container representation + content negotiation, byte ranges (`206`/`416`), conditional replacement (`428`/`412`/`204`), `If-Modified-Since` (`304`), recursive `Depth: infinity` delete, metadata links, the linkset resource, problem+json, RFC 9530 digest fields, `Prefer: set-linkset` and link-relation filtering, JSON Patch. |
| End-to-end | `EndToEndTest` — boots the bare-Jetty stack on a free port and drives CRUD, content negotiation, conditional requests, binary round-trip, delete guards, error codes, Merge Patch, subscriptions and the UI. |
| Authentication | `DidKeyValidatorTest`, `SsiCidValidatorTest`, `SamlValidatorTest`, `LwsCredentialValidatorTest`, `LwsOpenIdValidatorTest` (against an in-process `MockOidcProvider`), `OidcSsoRedirectTest`, `DpopValidatorTest`, `DpopNonceServiceTest`, `OutboundFetchPolicyTest`. |
| Authorization | `WacAclServiceTest` (owner control, public/authenticated, groups, `acl:origin`, inheritance, nearest-ACL override), `AccessGrantsTest`, `AccessNotificationTest`. |
| Notifications | `WebhookDeliveryTest` — boots the server + a real inbox, subscribes, makes a change, and verifies the RFC 9421 signature and RFC 9530 digest against the published JWKS. |
| Search | `SearchIndexTest`, `SearchIndexAuthzTest` (the authorization guarantees + pagination). |
| SPARQL endpoint | `FusekiSparqlEndpointTest`. |
| Storage / patch / config | `QuotaTest`, `ContainerPaginationTest`, `ResourceServiceListingTest`, `JsonMergePatchTest`, `JsonPatchTest`, `SparqlUpdateGuardTest`, `StorageDescriptionServiceTest`, `LwsConfigurationTest`. |
| Management UI | `LwsUiTest` (WicketTester): capability gating, resource creation, ACL editing. |

## Conventions

- **No Spring** outside the two bootstrap classes. New protocol logic is a plain Jakarta servlet/
  filter or a framework-free service object wired in `LwsComponents`.
- **Configuration** is added to `LwsConfiguration` via the typed, validating accessors so a bad value
  [fails fast](configuration.md#fail-fast-validation) with an actionable message.
- **Authorization** decisions go through the `Authorizer` so the HTTP API, UI and search services
  enforce the same rules.

## Documentation

This site is built from the Markdown in the
[`lws-server-docs`](https://github.com/ebremer/lws-server-docs) repository — see its `README.md` for
how to preview locally and publish via GitHub Pages.
