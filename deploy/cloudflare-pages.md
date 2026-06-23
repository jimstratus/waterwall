# Interim hosting: Cloudflare Pages

While the GitHub repo is still **private**, the KB site can be previewed live on Cloudflare
Pages without making the repo public and without granting Cloudflare access to it — using
**direct upload** of the built `site/_build/` directory. When the public GitHub repo exists, the
GitHub Pages Action (`.github/workflows/pages.yml`) takes over and this becomes optional.

The same `_build/` works at a domain root (Pages `*.pages.dev`) **and** under the `/waterwall/`
subpath (GitHub Pages) with no changes, because the generator emits **relative URLs only**.

## Prerequisites

- Node.js (for `wrangler` via `npx`).
- A Cloudflare account and an API token (or `wrangler login`). With a token, export it:
  ```bash
  export CLOUDFLARE_API_TOKEN=...        # token with "Pages: Edit"
  export CLOUDFLARE_ACCOUNT_ID=...
  ```

## Build

```bash
cd /path/to/waterwall
pip install -e ".[docs]"      # markdown + pygments + jinja2 + pyyaml
python site/build.py          # -> site/_build/
```

## One-time: create the Pages project

```bash
npx wrangler pages project create waterwall --production-branch master
```

## Deploy (each update)

```bash
npx wrangler pages deploy site/_build --project-name waterwall
```

Wrangler prints the deployment URL (e.g. `https://waterwall.pages.dev/` and a per-deploy
preview URL). Direct upload means Cloudflare only ever sees the built static output — never the
private repository or its history.

## Verify

```bash
curl -sf -o /dev/null -w "home  %{http_code}\n"  https://waterwall.pages.dev/index.html
curl -sf -o /dev/null -w "forAI %{http_code}\n"  https://waterwall.pages.dev/index.md
curl -sf -o /dev/null -w "llms  %{http_code}\n"  https://waterwall.pages.dev/llms.txt
```

All `200`. Click through the nav, confirm Mermaid diagrams render and the sidebar drawers on
mobile.

## Migrating to GitHub Pages (final)

Once the public `jimstratus/waterwall` repo exists with Pages enabled (source: GitHub Actions):

1. The `pages.yml` Action builds `site/` and deploys on every push to `master`.
2. The site serves under `https://jimstratus.github.io/waterwall/` — the relative URLs resolve
   under that subpath unchanged, so **no rebuild or config change** is needed.
3. Optionally keep Cloudflare Pages as a mirror, or delete the project:
   ```bash
   npx wrangler pages project delete waterwall
   ```
