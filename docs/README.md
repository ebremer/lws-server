# LWS Server — Documentation

Source for the **LWS Server** documentation website, a [Jekyll](https://jekyllrb.com/) site using the
[Just the Docs](https://just-the-docs.com/) theme. The published content lives in the Markdown pages
in this `docs/` folder of the lws-server repository; this README is for maintaining the site itself.
(It was a separate `lws-server-docs` repository until September 2026.)

## Publish on GitHub Pages

1. Push the lws-server repository to GitHub (default branch `master`).
2. **Settings → Pages → Build and deployment → Source: _Deploy from a branch_ → Branch: `master` →
   `/docs`.**
3. GitHub builds the site with its classic Jekyll builder and serves it at
   `https://<user>.github.io/lws-server/`.

The Just the Docs theme is pulled via `remote_theme` (pinned to a version compatible with GitHub's
classic Jekyll build), so no theme gem or custom build workflow is required.

> **`baseurl`.** [`_config.yml`](_config.yml) sets `baseurl: "/lws-server"` for a project page
> at `https://<user>.github.io/lws-server/`. If you serve from a **user/org page** or a **custom
> domain**, set `baseurl` to `""`.

## Preview locally

```bash
cd docs
bundle install
bundle exec jekyll serve --baseurl ""    # http://localhost:4000/
```

Requires Ruby (3.x) and Bundler.

## Editing

- Each page is a Markdown file with a Just the Docs front-matter block:
  ```yaml
  ---
  title: Configuration
  nav_order: 4
  ---
  ```
- The left-hand navigation order comes from `nav_order`; search is built automatically.
- Inline links between pages use relative `.md` paths (e.g. `[Configuration](configuration.md)`);
  `jekyll-relative-links` rewrites them for the built site, and they also work when browsing the
  repository on GitHub.

## Pages

| Page | File |
|---|---|
| Home | [`index.md`](index.md) |
| Getting Started | [`getting-started.md`](getting-started.md) |
| Architecture | [`architecture.md`](architecture.md) |
| Configuration | [`configuration.md`](configuration.md) |
| HTTP API | [`http-api.md`](http-api.md) |
| Metadata & Linksets | [`metadata-linksets.md`](metadata-linksets.md) |
| Authentication | [`authentication.md`](authentication.md) |
| Authorization | [`authorization.md`](authorization.md) |
| Notifications | [`notifications.md`](notifications.md) |
| Search & Type Index | [`search-type-index.md`](search-type-index.md) |
| SPARQL Endpoint | [`sparql-endpoint.md`](sparql-endpoint.md) |
| Deployment & TLS | [`deployment.md`](deployment.md) |
| Security | [`security.md`](security.md) |
| Management UI | [`management-ui.md`](management-ui.md) |
| Development | [`development.md`](development.md) |
