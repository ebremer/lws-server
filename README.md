# LWS Server — Documentation

Source for the **LWS Server** documentation website, a [Jekyll](https://jekyllrb.com/) site using the
[Just the Docs](https://just-the-docs.com/) theme. The published content lives in the Markdown pages
in this repository; this README is for maintaining the site itself.

## Publish on GitHub Pages

1. Push this repository to GitHub.
2. **Settings → Pages → Build and deployment → Source: _GitHub Actions_.**
3. The included workflow ([`.github/workflows/pages.yml`](.github/workflows/pages.yml)) builds the
   site with Jekyll 4 + Just the Docs and deploys it on every push to `main`.

> The workflow path is used (rather than “Deploy from a branch”) because current Just the Docs
> requires Jekyll 4, while GitHub’s classic branch build pins Jekyll 3.9.

## Preview locally

```bash
bundle install
bundle exec jekyll serve      # http://localhost:4000/
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
- Update the GitHub link in [`_config.yml`](_config.yml) (`aux_links`) if your source repository
  is not at `github.com/ebremer/lws-server`.

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
