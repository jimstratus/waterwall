"""Waterwall KB static-site generator. Pure Python; relative URLs only."""
from __future__ import annotations
from pathlib import Path
import html as html_lib
import json
import re
import shutil
import yaml
import markdown as md_lib
from jinja2 import Environment, FileSystemLoader, select_autoescape

SITE_DIR = Path(__file__).resolve().parent

_MERMAID_RE = re.compile(r"```mermaid\n(.*?)```", re.DOTALL)
_H1_RE = re.compile(r"<h1[^>]*>(.*?)</h1>", re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_PLACEHOLDER = "xMERMAIDx%dx"


def render_markdown(text: str) -> tuple[str, dict]:
    """Render Markdown -> (html, meta). Mermaid fences are stashed before
    highlighting so Pygments never touches them, then restored as
    <pre class="mermaid"> for client-side rendering."""
    blocks: list[str] = []

    def _stash(match: re.Match) -> str:
        blocks.append(match.group(1))
        return _PLACEHOLDER % (len(blocks) - 1)

    stashed = _MERMAID_RE.sub(_stash, text)
    converter = md_lib.Markdown(
        extensions=[
            "fenced_code", "codehilite", "tables", "toc",
            "admonition", "attr_list", "def_list",
        ],
        extension_configs={"codehilite": {"guess_lang": False}},
    )
    html = converter.convert(stashed)
    toc = getattr(converter, "toc", "")
    for i, block in enumerate(blocks):
        pre = f'<pre class="mermaid">{block.strip()}</pre>'
        # Markdown wraps the lone placeholder in <p>…</p>; strip that wrapper.
        html = html.replace(f"<p>{_PLACEHOLDER % i}</p>", pre).replace(_PLACEHOLDER % i, pre)
    title_match = _H1_RE.search(html)
    title = html_lib.unescape(_TAG_RE.sub("", title_match.group(1)).strip()) if title_match else ""
    return html, {"toc": toc, "title": title}


def load_config(root: Path = SITE_DIR) -> dict:
    return yaml.safe_load((root / "config.yaml").read_text(encoding="utf-8"))


def load_nav(root: Path = SITE_DIR) -> list[dict]:
    return yaml.safe_load((root / "nav.yaml").read_text(encoding="utf-8"))


def iter_pages(nav: list[dict]):
    """Depth-first yield of every nav node that has a 'page'."""
    for node in nav:
        if node.get("page"):
            yield node
        for child in node.get("children", []) or []:
            if child.get("page"):
                yield child


def relative_url(from_page: str, to_page: str, ext: str = ".html") -> str:
    """Output is a flat directory, so a relative link is just the filename.
    Keeps every link portable across a domain root (Cloudflare Pages) and a
    /waterwall/ subpath (GitHub Pages) with no base_url to configure."""
    return f"{to_page}{ext}"


def render_nav(nav: list[dict], current: str) -> str:
    parts = ['<ul class="nav-root">']
    for node in nav:
        if node.get("children"):
            parts.append(
                f'<li class="nav-group"><span class="nav-group-title">{node["title"]}</span><ul>'
            )
            for child in node["children"]:
                active = " active" if child.get("page") == current else ""
                href = relative_url(current, child["page"])
                parts.append(
                    f'<li class="nav-item{active}"><a href="{href}">{child["title"]}</a></li>'
                )
            parts.append("</ul></li>")
        else:
            active = " active" if node.get("page") == current else ""
            href = relative_url(current, node["page"])
            parts.append(
                f'<li class="nav-item{active}"><a href="{href}">{node["title"]}</a></li>'
            )
    parts.append("</ul>")
    return "".join(parts)


_PARA_RE = re.compile(r"<p>(.*?)</p>", re.DOTALL)


def summary_of(html: str) -> str:
    """First non-empty paragraph as plain text, capped at 200 chars."""
    for para in _PARA_RE.findall(html):
        text = html_lib.unescape(_TAG_RE.sub("", para)).strip()
        if text:
            return (text[:197] + "…") if len(text) > 200 else text
    return ""


def _copy_static(out: Path) -> None:
    src = SITE_DIR / "static"
    if src.exists():
        shutil.copytree(src, out / "static", dirs_exist_ok=True)


def build(out: Path | None = None) -> Path:
    out = out or (SITE_DIR / "_build")
    out.mkdir(parents=True, exist_ok=True)
    cfg = load_config()
    nav = load_nav()
    env = Environment(
        loader=FileSystemLoader(str(SITE_DIR / "templates")),
        autoescape=select_autoescape(["html"]),
    )
    tmpl = env.get_template("page.html.j2")
    records: list[dict] = []
    for node in iter_pages(nav):
        page = node["page"]
        src = SITE_DIR / "content" / f"{page}.md"
        raw = src.read_text(encoding="utf-8")
        html, meta = render_markdown(raw)
        page_title = meta["title"] or node["title"]
        rendered = tmpl.render(
            config=cfg,
            page=page,
            page_title=page_title,
            content=html,
            nav_html=render_nav(nav, page),
        )
        (out / f"{page}.html").write_text(rendered, encoding="utf-8")
        (out / f"{page}.md").write_text(raw, encoding="utf-8")  # raw "for AI"
        records.append({
            "title": page_title,
            "page": page,
            "url": f"{page}.html",
            "summary": summary_of(html),
            "text": _TAG_RE.sub(" ", html),
        })
    llms = env.get_template("llms.txt.j2").render(config=cfg, pages=records)
    (out / "llms.txt").write_text(llms, encoding="utf-8")
    search = [{"title": r["title"], "url": r["url"], "text": r["text"][:5000]} for r in records]
    (out / "search-index.json").write_text(json.dumps(search), encoding="utf-8")
    _copy_static(out)
    return out


if __name__ == "__main__":
    dest = build()
    print(f"built -> {dest}")
