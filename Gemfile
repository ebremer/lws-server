source "https://rubygems.org"

# Matches GitHub Pages' classic build ("Deploy from a branch"): the github-pages gem pins the exact
# Jekyll + plugin versions GitHub runs, and bundles jekyll-remote-theme (used to pull Just the Docs)
# and jekyll-relative-links. The theme itself is set via `remote_theme:` in _config.yml.
#
# Local preview (serve at the site root rather than the /lws-server-docs baseurl):
#
#   bundle install
#   bundle exec jekyll serve --baseurl ""    # http://localhost:4000/
#
gem "github-pages", group: :jekyll_plugins

# Local server helper for Ruby 3.x (webrick is no longer bundled with Ruby).
gem "webrick", "~> 1.8"
