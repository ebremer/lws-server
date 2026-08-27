# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately to **erich@ebremer.com**. If you would like to encrypt the report, say so in a
first message and a key will be arranged.

Please include, as far as you have them:

- what the issue is and why it is a problem;
- the configuration it needs — `lws.access-control` (`owner` or `wac`), whether `lws.owners` is set,
  whether `lws.dev.open` is on, and any other `lws.*` settings that matter;
- steps to reproduce, ideally as `curl` commands or a small test;
- what an attacker gets out of it.

You can expect an acknowledgement within a few days. Fixes are prioritised by what an attacker can
reach and with what privileges — an unauthenticated remote issue ahead of one that needs an existing
account, which is ahead of one that needs operator access.

## Supported versions

This project has not yet cut a release. Security fixes land on the default branch; there is no
backport stream. If you are running it, run it from a recent commit.

## Scope

In scope: anything reachable over HTTP against a correctly configured storage — the LWS protocol
surface, the authentication suites (WebID/OIDC, DPoP, `did:key`, SAML), Web Access Control, access
grants, notifications and their outbound deliveries, the Wicket console, and the optional SPARQL
endpoint.

Out of scope, because they are documented behaviour rather than defects:

- `lws.dev.open=true`, which exists to permit two development postures and says so at startup;
- `lws.ui.dev-login=true`, which is impersonation by design and is refused off-loopback and behind a
  proxy;
- `lws.sparql.read-only=false`, which grants unauthenticated write access to the whole dataset by
  request;
- allow-listing a private host via `lws.webhook.allowed-hosts` or
  `lws.sparql-update.allowed-hosts`, which is how an operator deliberately opts into a target the
  SSRF guards would otherwise refuse.

If one of those does something other than what it says, that *is* in scope — the concern is a
control that does not do what it claims, not one an operator knowingly turned off.

## A note on this repository's own documents

`REVIEW.md`, `TODO.md` and `REVIEW-lws-server.md` are the working record of an internal security
review. They describe findings that are **not yet fixed**, with file-and-line pointers and, in
places, enough detail to reproduce them. That is deliberate — they exist so the work can be picked up
where it was left — but it means this repository should not be made public while any unfixed finding
in them is still unfixed. Check the "Resume here" section at the top of `TODO.md` before publishing.
