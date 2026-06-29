from pathlib import Path
import importlib.util
import json
import shutil
import tempfile

SITE = Path(__file__).resolve().parents[1] / "site"


def _build_mod():
    spec = importlib.util.spec_from_file_location("kb_build", SITE / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_load_config_and_nav():
    m = _build_mod()
    cfg = m.load_config(SITE)
    assert cfg["title"] == "Waterwall"
    assert cfg["issues_url"].endswith("/issues")
    nav = m.load_nav(SITE)
    titles = [n["title"] for n in nav]
    assert "Home" in titles
    # nav nodes always expose title + (page or children)
    for n in nav:
        assert "title" in n and ("page" in n or "children" in n)


def test_render_markdown_mermaid_and_code():
    m = _build_mod()
    md = "# Hello\n\n```mermaid\nflowchart LR\n A-->B\n```\n\n```python\nx = 1\n```\n"
    html, meta = m.render_markdown(md)
    assert meta["title"] == "Hello"
    # mermaid block emitted verbatim for client-side rendering
    assert '<pre class="mermaid">' in html
    assert "flowchart LR" in html
    # python block IS syntax-highlighted by pygments/codehilite
    assert "codehilite" in html or "highlight" in html
    # the mermaid graph must NOT have been swept into a highlighted block
    mermaid_chunk = html.split('<pre class="mermaid">')[1].split("</pre>")[0]
    assert "flowchart LR" in mermaid_chunk
    assert "codehilite" not in mermaid_chunk


def test_relative_url_across_depth():
    m = _build_mod()
    assert m.relative_url("index", "onboarding") == "onboarding.html"
    assert m.relative_url("onboarding", "index") == "index.html"


def test_build_emits_html_and_raw_md_with_relative_links():
    m = _build_mod()
    out = Path(tempfile.mkdtemp()) / "_build"
    m.build(out)
    nav = m.load_nav(SITE)
    for node in m.iter_pages(nav):
        assert (out / f"{node['page']}.html").exists(), node
        assert (out / f"{node['page']}.md").exists(), node
    home = (out / "index.html").read_text(encoding="utf-8")
    # raw-md "for AI" link present and relative
    assert 'href="index.md"' in home
    # no absolute site paths leaked
    assert 'href="/' not in home and 'src="/' not in home
    shutil.rmtree(out, ignore_errors=True)


def test_build_emits_llms_and_search_index():
    m = _build_mod()
    out = Path(tempfile.mkdtemp()) / "_build"
    m.build(out)
    llms = (out / "llms.txt").read_text(encoding="utf-8")
    assert "Waterwall" in llms and "index.md" in llms
    idx = json.loads((out / "search-index.json").read_text(encoding="utf-8"))
    assert any(e["url"] == "index.html" for e in idx)
    assert all({"title", "url", "text"} <= set(e) for e in idx)
    shutil.rmtree(out, ignore_errors=True)


def test_build_copies_static_assets():
    m = _build_mod()
    out = Path(tempfile.mkdtemp()) / "_build"
    m.build(out)
    for asset in ["styles.css", "app.js", "favicon.svg", "mermaid.min.js", "lunr.min.js"]:
        assert (out / "static" / asset).exists(), asset
    shutil.rmtree(out, ignore_errors=True)


def test_full_build_every_nav_page_renders():
    m = _build_mod()
    out = Path(tempfile.mkdtemp()) / "_build"
    m.build(out)
    nav = m.load_nav(SITE)
    pages = list(m.iter_pages(nav))
    assert len(pages) >= 12
    for node in pages:
        html = (out / f"{node['page']}.html").read_text(encoding="utf-8")
        assert "<article" in html
        assert f'href="{node["page"]}.md"' in html  # for-AI link
        assert 'href="/' not in html  # relative links only
    assert (out / "llms.txt").exists() and (out / "search-index.json").exists()
    shutil.rmtree(out, ignore_errors=True)


def test_no_internal_doc_or_host_leakage():
    # Published content must not leak internal docs, host names, infra IDs, or IPs.
    content = SITE / "content"
    banned = [
        "lab-notes", "HANDOFF", "RESEARCH.md", "superpowers",
        "test-host", "prod-host", "edge-host.example.com", "bastion.example.com",
        "100.96.0", "10.20.31", "914f6a8b", "5.252.55",
    ]
    for md in content.glob("*.md"):
        text = md.read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, f"{md.name} leaks '{token}'"
