(function () {
  "use strict";

  /* ---- Sidebar: expanded on desktop, drawer on mobile (persisted) ---- */
  var body = document.body;
  var toggle = document.getElementById("nav-toggle");
  if (localStorage.getItem("ww-nav") === "open") body.classList.add("nav-open");
  if (toggle) {
    toggle.addEventListener("click", function () {
      body.classList.toggle("nav-open");
      localStorage.setItem("ww-nav", body.classList.contains("nav-open") ? "open" : "closed");
    });
  }

  /* ---- Mermaid with the cyberpunk palette ---- */
  if (window.mermaid) {
    window.mermaid.initialize({
      startOnLoad: true,
      theme: "base",
      themeVariables: {
        background: "#050505",
        primaryColor: "#001818",
        primaryBorderColor: "#00aaaa",
        primaryTextColor: "#c0c0c0",
        secondaryColor: "#0a0a0a",
        tertiaryColor: "#050505",
        lineColor: "#00ff41",
        textColor: "#c0c0c0",
        fontFamily: "JetBrains Mono, monospace",
        noteBkgColor: "#0a0a0a",
        noteTextColor: "#ffaa00",
        noteBorderColor: "#ffaa00"
      }
    });
  }

  /* ---- Copy buttons on code blocks ---- */
  document.querySelectorAll("div.codehilite, .markdown-body > pre").forEach(function (block) {
    if (block.classList.contains("mermaid")) return;
    var btn = document.createElement("button");
    btn.className = "copy-btn";
    btn.type = "button";
    btn.textContent = "copy";
    btn.addEventListener("click", function () {
      var code = block.querySelector("code") || block;
      navigator.clipboard.writeText(code.innerText).then(function () {
        btn.textContent = "copied";
        setTimeout(function () { btn.textContent = "copy"; }, 1200);
      });
    });
    if (getComputedStyle(block).position === "static") block.style.position = "relative";
    block.appendChild(btn);
  });

  /* ---- Client search (lunr over search-index.json) ---- */
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  var searchBox = document.getElementById("search-box");
  var resultsEl = document.getElementById("search-results");
  if (searchBox && resultsEl && window.lunr) {
    var idx = null, docs = [];
    var loaded = false;

    function ensureIndex() {
      if (loaded) return Promise.resolve();
      return fetch("search-index.json")
        .then(function (r) { return r.json(); })
        .then(function (data) {
          docs = data;
          idx = window.lunr(function () {
            this.ref("url");
            this.field("title", { boost: 10 });
            this.field("text");
            data.forEach(function (d) { this.add(d); }, this);
          });
          loaded = true;
        });
    }

    function render(matches) {
      if (!matches.length) {
        resultsEl.innerHTML = '<div class="sr-empty">no matches</div>';
        resultsEl.hidden = false;
        return;
      }
      resultsEl.innerHTML = matches.slice(0, 12).map(function (m) {
        var d = docs.find(function (x) { return x.url === m.ref; });
        if (!d) return "";
        var snip = (d.text || "").slice(0, 120).trim();
        return '<a href="' + esc(d.url) + '"><span class="sr-title">' + esc(d.title) + "</span><br>" +
               '<span class="sr-snip">' + esc(snip) + "…</span></a>";
      }).join("");
      resultsEl.hidden = false;
    }

    searchBox.addEventListener("input", function () {
      var q = searchBox.value.trim();
      if (q.length < 2) { resultsEl.hidden = true; return; }
      ensureIndex().then(function () {
        var matches = [];
        try { matches = idx.search(q + " " + q + "*"); } catch (e) { matches = []; }
        render(matches);
      });
    });
    document.addEventListener("click", function (e) {
      if (!resultsEl.contains(e.target) && e.target !== searchBox) resultsEl.hidden = true;
    });
  }
})();
