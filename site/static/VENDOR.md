# Vendored static assets

Pinned third-party files bundled with the KB site so it builds and renders
fully offline (no runtime CDN dependency).

| File | Upstream | Version | License |
|---|---|---|---|
| `mermaid.min.js` | https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js | 11.x | MIT |
| `lunr.min.js` | https://cdn.jsdelivr.net/npm/lunr@2.3.9/lunr.min.js | 2.3.9 | MIT |
| `fonts/jetbrains-mono-400.woff2` | fontsource `jetbrains-mono` latin 400 | latest | OFL-1.1 |
| `fonts/jetbrains-mono-700.woff2` | fontsource `jetbrains-mono` latin 700 | latest | OFL-1.1 |

To refresh: re-run the `curl` commands in `docs/superpowers/plans/2026-06-23-waterwall-kb-site.md` (Task 5).
