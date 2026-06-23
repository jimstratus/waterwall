/* webgui/app.js
   Read-only web status page for Waterwall.
   Polls the `endpoint` URL (default `admin/state`, relative to the
   page URL) at 1 Hz; mirrors the TUI 1:1. No build step, no deps.

   The endpoint field is the FULL state-snapshot URL, not a path
   prefix — it gets passed straight to fetch(). Defaults to relative
   `admin/state` so the page works at both `/` (legacy/dev) and
   `/waterwall/` (path-prefixed reverse-proxy) deployments without
   any per-environment tweaks.

   `useMock` defaults to false: opening the page against a running
   admin server shows live data. Flip the "use mock" checkbox on
   to render with synthetic state instead (useful for evaluating
   the page or taking screenshots).
*/

(() => {
  'use strict';

  // ---------------------------------------------------------------- config

  const DEFAULT_ENDPOINT = 'admin/state';      // relative — resolves against page path
  const POLL_INTERVAL_MS = 1000;
  const FETCH_TIMEOUT_MS = 1500;
  const ACTIVITY_VISIBLE = 50;            // rows kept in the DOM
  const ACTIVITY_TAIL_THRESHOLD_PX = 30;  // "near bottom" detection

  const STORAGE_KEY = 'waterwall-webgui-v1';

  // ---------------------------------------------------------------- state

  const ui = {
    endpointInput: document.getElementById('endpoint-input'),
    useMockInput:   document.getElementById('use-mock'),
    viewButtons:    Array.from(document.querySelectorAll('.view-btn')),
    frame:          document.getElementById('frame'),
    hostname:       document.getElementById('hostname'),
    statusChip:     document.getElementById('status-chip'),
    offlineBanner:  document.getElementById('offline-banner'),
    bodies: {
      activity:       document.getElementById('body-activity'),
      counters:       document.getElementById('body-counters'),
      map:            document.getElementById('body-map-patterns'),
      killswitch:     document.getElementById('body-killswitch'),
      chain:          document.getElementById('body-chain'),
      sessions:       document.getElementById('body-sessions'),
    },
    tailPill:       document.getElementById('tail-pill'),
    tailPillCount:  document.getElementById('tail-pill-count'),
    pollIndicator:  document.getElementById('poll-indicator'),
    pollDot:        document.getElementById('poll-dot'),
    pollText:       document.getElementById('poll-text'),
  };

  // Runtime state
  const st = {
    endpoint: DEFAULT_ENDPOINT,
    useMock:  false,                       // default: hit the real admin server
    view:     'healthy',
    isOffline: false,
    offlineReason: '',
    lastSnapshot: null,
    seenEventKeys: new Set(),    // dedupe for activity
    pendingNewEvents: 0,
    pollOk: 0,
    pollFail: 0,
    pollTimer: null,
    inFlight: false,
  };

  // ---------------------------------------------------------------- utils

  // Escape for safe insertion into innerHTML
  const esc = (s) => String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  // Em-dash for null / undefined / empty string. Never "0", never "".
  const em = (v) => (v === null || v === undefined || v === '' ? '—' : v);
  const emHtml = (v) => (v === null || v === undefined || v === ''
    ? '<span class="val is-empty">—</span>'
    : `<span class="val">${esc(v)}</span>`);

  const shortHash = (h) => {
    if (!h) return '—';
    const s = String(h);
    return s.length > 8 ? `${s.slice(0, 8)}…` : s;
  };
  const shortId = (id) => {
    if (!id) return '—';
    const s = String(id);
    return s.length > 8 ? s.slice(0, 8) : s;
  };

  // Extract HH:MM:SS.mmm from an ISO 8601 timestamp. Preserves
  // milliseconds and handles both positive (+00:00) and negative
  // (-05:00) timezone offsets. Drops the timezone suffix. Returns
  // '—' for null/garbage.
  const timeOnly = (iso) => {
    if (!iso) return '—';
    // Strip timezone: +/-HH:MM or Z suffix. A simple split on [+Z]
    // misses negative offsets; use a regex to isolate the time portion.
    const timePart = String(iso).split('T').pop();
    return timePart.replace(/[+-]\d{2}:\d{2}$/, '').replace(/Z$/, '') || '—';
  };

  // Parse an ISO timestamp into a Date. null on failure.
  const parseIso = (iso) => {
    if (!iso) return null;
    const cleaned = String(iso).replace(/Z$/, '+00:00');
    const d = new Date(cleaned);
    return isNaN(d.getTime()) ? null : d;
  };

  const humanizeUptime = (sec) => {
    if (!sec || sec <= 0) return '—';
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (h) return `${h}h ${m}m`;
    return `${m}m`;
  };

  const humanizeUptimeShort = (sec) => {
    if (!sec || sec <= 0) return '—';
    const s = Math.floor(sec);
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m`;
    const h = Math.floor(m / 60);
    const rem = m - h * 60;
    return rem ? `${h}h ${rem}m` : `${h}h`;
  };

  // Format a number with thousands separators
  const fmtNum = (n) => (n === null || n === undefined ? '—' : Number(n).toLocaleString('en-US'));

  // Stable key for activity events
  const eventKey = (evt) => `${evt.ts || ''}|${evt.direction || ''}|${evt.request_id || ''}`;

  // Hostname chip: TUI uses socket.gethostname().split('.')[0].uppercased()
  const shortHostname = () => {
    const h = window.location.hostname || 'localhost';
    return h.split('.')[0].toUpperCase() || 'LOCALHOST';
  };

  // ---------------------------------------------------------------- fetch

  async function fetchWithTimeout(url, timeoutMs) {
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const r = await fetch(url, { signal: ctrl.signal, cache: 'no-store' });
      return r;
    } finally {
      clearTimeout(tid);
    }
  }

  async function fetchState() {
    if (st.useMock) {
      if (st.view === 'offline') {
        const e = new Error('simulated offline — proxy unreachable');
        e.simulated = true;
        throw e;
      }
      return mockState(st.view);
    }
    const r = await fetchWithTimeout(st.endpoint, FETCH_TIMEOUT_MS);
    if (r.status !== 200) {
      throw new Error(`proxy returned ${r.status}`);
    }
    let data;
    try { data = await r.json(); }
    catch (e) { throw new Error(`invalid JSON: ${e.message}`); }
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error(`non-object JSON: ${Array.isArray(data) ? 'array' : typeof data}`);
    }
    return data;
  }

  // ---------------------------------------------------------------- render: counters

  function renderBar(value, scale, widthPx = 130) {
    const scaleSafe = Math.max(1, scale || 1);
    const pct = Math.max(0, Math.min(1, (value || 0) / scaleSafe));
    return `<div class="bar" style="width:${widthPx}px"><span class="bar-fill" style="width:${(pct * 100).toFixed(1)}%"></span></div>`;
  }

  function renderCounters(c) {
    const rpm  = c.redactions_per_min;
    const top  = c.top_types || [];
    const p50  = c.latency_p50_ms;
    const p99  = c.latency_p99_ms;
    const unk  = c.unknown_placeholders;

    const maxTop = top.length ? Math.max(...top.map(t => t.count || 0)) : 1;

    const topRows = top.length
      ? top.slice(0, 5).map(t => {
          const label = em(t.type);
          const count = t.count ?? 0;
          return `<div class="bar-row">
            <span class="lbl">${esc(label)}</span>
            <span class="num">${fmtNum(count)}</span>
            ${renderBar(count, maxTop)}
          </div>`;
        }).join('')
      : `<div class="bar-row"><span class="lbl">Top types:</span><span class="val is-empty">—</span></div>`;

    return `
      <div class="bar-row">
        <span class="lbl">Redactions/min:</span>
        <span class="num">${fmtNum(rpm)}</span>
        ${renderBar(rpm, Math.max(20, rpm || 1))}
      </div>
      <div class="bar-row">
        <span class="lbl" style="font-style:italic">Top types:</span>
        <span class="num"></span>
        <span></span>
      </div>
      ${topRows}
      <div class="kv" style="margin-top:6px">
        <span class="lbl">Latency p50:</span>${emHtml(p50 !== undefined && p50 !== null ? `${p50} ms` : null)}
        <span class="lbl">Latency p99:</span>${emHtml(p99 !== undefined && p99 !== null ? `${p99} ms` : null)}
        <span class="lbl">Unknown placeholders:</span>${emHtml(unk)}
      </div>
    `;
  }

  // ---------------------------------------------------------------- render: kill switch

  function renderKillswitch(ks) {
    const active = !!(ks && ks.active);
    const sources = [
      ['config',  ks && ks.config],
      ['sigusr1', ks && ks.sigusr1],
      ['sentinel', ks && ks.sentinel],
      ['http',    ks && ks.http],
    ];

    const banner = active
      ? `<div class="ks-banner is-armed">▆▆▆ ARMED — BLOCKING ALL TRAFFIC ▆▆▆</div>
         <div class="ks-sub is-armed">fail-closed — every request returns HTTP 502</div>`
      : `<div class="ks-banner is-disarmed">● DISARMED — NORMAL OPERATION</div>
         <div class="ks-sub">passing — redaction + detokenization active</div>`;

    const sourcesHtml = sources.map(([name, isOn]) => `
      <div class="ks-source ${isOn ? 'is-armed' : 'is-disarmed'}">
        <span class="name">${name}</span>
        <span class="state">${isOn ? '● armed' : '✗ disarmed'}</span>
      </div>
    `).join('');

    const asserted = active
      ? sources.filter(([, v]) => v).map(([n]) => n).join(', ')
      : '';
    const assertedHtml = active
      ? `<div class="ks-asserted">Asserted by: ${esc(asserted)}</div>`
      : '';

    return banner + `<div class="ks-sources">${sourcesHtml}</div>` + assertedHtml;
  }

  // ---------------------------------------------------------------- render: map + patterns

  function renderMapPatterns(state) {
    const m  = state.map || {};
    const p  = state.patterns || {};
    const bd = p.breakdown || {};
    const size  = m.size, cap = m.capacity, ttl = m.ttl_seconds;
    const count = p.count, base = bd.base, ext = bd.ext, pem = bd.pem;
    const phash = p.hash, lastReload = p.last_reload_ts;

    let sizeLine;
    if (size === null || size === undefined || cap === null || cap === undefined) {
      sizeLine = `<span class="lbl">Map size:</span>${emHtml(null)}`;
    } else {
      const pct = cap > 0 ? (size / cap * 100) : 0;
      sizeLine = `<span class="lbl">Map size:</span><span class="val">${fmtNum(size)} / ${fmtNum(cap)} <span class="map-pct">(${pct.toFixed(1)}%)</span></span>`;
    }

    const ttlLine = ttl
      ? `<span class="lbl">TTL:</span><span class="val map-ttl">${Math.floor(ttl / 3600)} h</span>`
      : `<span class="lbl">TTL:</span>${emHtml(null)}`;

    let patLine;
    if (count !== null && count !== undefined &&
        base !== null && base !== undefined &&
        ext !== null && ext !== undefined &&
        pem !== null && pem !== undefined) {
      patLine = `<span class="lbl">Patterns:</span><span class="val">${fmtNum(base)} base + ${fmtNum(ext)} ext + ${fmtNum(pem)} PEM = ${fmtNum(count)} total</span>`;
    } else {
      patLine = `<span class="lbl">Patterns:</span>${emHtml(null)}`;
    }

    return `
      <div class="kv">
        ${sizeLine}
        ${ttlLine}
        ${patLine}
        <span class="lbl">Policy hash:</span>${emHtml(shortHash(phash))}
        <span class="lbl">Last reload:</span>${emHtml(timeOnly(lastReload))}
      </div>
    `;
  }

  // ---------------------------------------------------------------- render: chain

  function renderChain(c) {
    const lines    = c.lines;
    const cps      = c.checkpoints;
    const lastSig  = c.last_signed_ts;
    const cpRoot   = c.last_checkpoint_root_hash;
    const head     = c.current_head_prev_hash;
    const verify   = c.verify_status;

    const verifyClass = verify === 'ok' ? 'is-ok' : 'is-fail';
    const verifyGlyph = verify === 'ok' ? '●' : '✗';

    return `
      <div class="kv">
        <span class="lbl">Lines:</span>${emHtml(fmtNum(lines))}
        <span class="lbl">Checkpoints:</span>${emHtml(fmtNum(cps))}
        <span class="lbl">Checkpoint root:</span><span class="val">${esc(shortHash(cpRoot))}<span class="chain-meta">(last signed: ${esc(timeOnly(lastSig))})</span></span>
        <span class="lbl">Live chain head:</span><span class="val">${esc(shortHash(head))}<span class="chain-meta">(unsigned, every line)</span></span>
        <span class="lbl">Verify status:</span><span class="val chain-verify ${verifyClass}">${esc((verify || '—').toString().toUpperCase())}  ${verifyGlyph}</span>
      </div>
    `;
  }

  // ---------------------------------------------------------------- render: sessions

  function renderSessions(sessions, nowIso) {
    if (!sessions || sessions.length === 0) {
      return `<div class="sessions-empty">—  no active sessions</div>`;
    }
    const now = parseIso(nowIso) || new Date();
    const rows = sessions.map(s => {
      const sid = shortId(s.session_id);
      const red = fmtNum(s.redactions);
      const started = parseIso(s.started_ts);
      let up = '—';
      if (started) {
        const delta = Math.floor((now.getTime() - started.getTime()) / 1000);
        up = humanizeUptimeShort(delta);
      }
      return `<tr>
        <td>${esc(sid)}</td>
        <td class="num">${esc(red)}</td>
        <td class="up">${esc(up)}</td>
      </tr>`;
    }).join('');
    return `
      <table class="sessions-table">
        <thead><tr><th>Session</th><th style="text-align:right">Redactions</th><th>Uptime</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `;
  }

  // ---------------------------------------------------------------- render: activity

  function renderActivityEvents(events) {
    if (!events || events.length === 0) {
      return `<div class="activity-empty">—  no activity yet</div>`;
    }
    const out = [];
    for (const evt of events) {
      const ts  = em(evt.ts);
      const dir = (evt.direction || '?').toUpperCase();
      const req = em(evt.request_id);
      const dirClass = (dir === 'OUT') ? 'activity-out'
                     : (dir === 'IN')  ? 'activity-in'
                     : (dir === 'WARN')? 'activity-warn'
                     : (dir === 'ERR') ? 'activity-err'
                     : 'activity-blank';
      let countText = '';
      if (dir === 'OUT') {
        const n = evt.redactions ?? 0;
        countText = `${n} redacts`;
      } else if (dir === 'IN') {
        const n = evt.detok_count ?? 0;
        countText = `${n} detok`;
      } else {
        countText = '';
      }
      out.push(`
        <div class="activity-row ${dirClass}">
          <span class="ts">${esc(ts)}</span>
          <span class="dir">${esc(dir)}</span>
          <span class="req">${esc(req)}</span>
          <span class="num">${esc(countText)}</span>
        </div>
      `);
      if (dir === 'OUT' && Array.isArray(evt.types) && evt.types.length) {
        const typesHtml = evt.types.map(t =>
          // `blocked` only exists in mock armed mode; real /admin/state
          // JSON never has this field. The is-blocked CSS class is defined
          // for the mock demo but inactive against the real server.
          `<span class="pill${evt.blocked ? ' is-blocked' : ''}">${esc(t)}</span>`
        ).join('');
        out.push(`<div class="activity-types">${typesHtml}</div>`);
      } else if (dir === 'OUT' && evt.blocked) {
        out.push(`<div class="activity-types"><span class="pill is-blocked">BLOCKED</span></div>`);
      }
    }
    return out.join('');
  }

  function applyActivity(newEvents) {
    const body = ui.bodies.activity;

    // Detect "near bottom" BEFORE rendering, so we can decide to auto-scroll.
    const distFromBottom = body.scrollHeight - body.scrollTop - body.clientHeight;
    const wasAtBottom = distFromBottom <= ACTIVITY_TAIL_THRESHOLD_PX;

    // Find new events not seen in the previous snapshot
    let newCount = 0;
    for (const evt of newEvents) {
      const k = eventKey(evt);
      if (!st.seenEventKeys.has(k)) {
        st.seenEventKeys.add(k);
        newCount++;
      }
    }
    // Bounded set: keep at most 4× the visible window so the Set doesn't grow forever.
    if (st.seenEventKeys.size > ACTIVITY_VISIBLE * 4) {
      // Crude trim: rebuild from the last ACTIVITY_VISIBLE * 2 events
      st.seenEventKeys = new Set(newEvents.slice(-ACTIVITY_VISIBLE * 2).map(eventKey));
    }

    // Render the most recent N
    const slice = newEvents.slice(-ACTIVITY_VISIBLE);
    body.innerHTML = renderActivityEvents(slice);

    // If the user was at the bottom, follow the tail; else show the pill
    if (wasAtBottom) {
      body.scrollTop = body.scrollHeight;
      hideTailPill();
    } else {
      st.pendingNewEvents += newCount;
      if (st.pendingNewEvents > 0) {
        showTailPill();
      }
    }
  }

  function showTailPill() {
    ui.tailPillCount.textContent = String(st.pendingNewEvents);
    ui.tailPill.hidden = false;
  }
  function hideTailPill() {
    st.pendingNewEvents = 0;
    ui.tailPill.hidden = true;
  }

  // ---------------------------------------------------------------- apply: online

  function applyOnline(state) {
    st.lastSnapshot = state;

    // Exit OFFLINE if we were in it
    if (st.isOffline) {
      st.isOffline = false;
      st.offlineReason = '';
      ui.frame.classList.remove('is-offline');
      ui.offlineBanner.textContent = '';
    }

    // Status chip
    const isOk = state.status === 'ok';
    ui.statusChip.className = `status-chip ${isOk ? 'status-good' : 'status-fail'}`;
    if (isOk) {
      ui.statusChip.textContent = `●UP  uptime ${humanizeUptime(state.uptime_seconds)}`;
    } else {
      ui.statusChip.textContent = `●FAIL  /healthz reports unhealthy`;
    }

    // Panels
    ui.bodies.counters.innerHTML  = renderCounters(state.counters_5m || {});
    ui.bodies.killswitch.innerHTML = renderKillswitch(state.killswitch || {});
    ui.bodies.map.innerHTML        = renderMapPatterns(state);
    ui.bodies.chain.innerHTML     = renderChain(state.chain || {});
    ui.bodies.sessions.innerHTML  = renderSessions(state.sessions || [], state.ts);

    // Activity: tail-aware
    applyActivity(state.recent_activity || []);
  }

  // ---------------------------------------------------------------- apply: offline

  function applyOffline(reason) {
    st.isOffline = true;
    st.offlineReason = reason;
    st.lastSnapshot = null;
    st.seenEventKeys = new Set();
    st.pendingNewEvents = 0;
    hideTailPill();

    ui.frame.classList.add('is-offline');
    // Banner with the reason (truncated to keep the row single-line)
    const truncated = String(reason || 'unknown error').slice(0, 220);
    ui.offlineBanner.innerHTML = `PROXY OFFLINE — RUN <code>waterwall verify-install</code><span class="reason">(${esc(truncated)})</span>`;

    ui.statusChip.className = 'status-chip status-fail';
    ui.statusChip.textContent = '●OFFLINE  proxy unreachable';

    // Blank all panels with the offline marker
    for (const id of ['counters', 'killswitch', 'map', 'chain', 'sessions', 'activity']) {
      ui.bodies[id].innerHTML = `<div class="activity-empty">—  proxy offline</div>`;
    }
  }

  // ---------------------------------------------------------------- tick

  async function tick() {
    if (st.inFlight) return;
    st.inFlight = true;
    try {
      const snap = await fetchState();
      st.pollOk++;
      ui.pollIndicator.classList.add('is-ok');
      ui.pollIndicator.classList.remove('is-fail');
      ui.pollText.textContent = `poll ok × ${st.pollOk}`;
      applyOnline(snap);
    } catch (e) {
      st.pollFail++;
      ui.pollIndicator.classList.add('is-fail');
      ui.pollIndicator.classList.remove('is-ok');
      ui.pollText.textContent = `poll fail × ${st.pollFail}`;
      applyOffline(e.message || String(e));
    } finally {
      st.inFlight = false;
    }
  }

  function startPolling() {
    stopPolling();
    // Stagger: tick immediately, then on interval
    tick();
    st.pollTimer = setInterval(tick, POLL_INTERVAL_MS);
  }
  function stopPolling() {
    if (st.pollTimer) {
      clearInterval(st.pollTimer);
      st.pollTimer = null;
    }
  }

  // ---------------------------------------------------------------- controls

  function wireControls() {
    // Load saved prefs
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const prefs = JSON.parse(raw);
        if (prefs.endpoint) st.endpoint = prefs.endpoint;
        if (typeof prefs.useMock === 'boolean') st.useMock = prefs.useMock;
        if (prefs.view) st.view = prefs.view;
      }
    } catch (_) { /* ignore */ }

    // One-time migration: the previous default was the root-relative
    // "/admin/state". When the page is served from a path prefix
    // (e.g. /waterwall/), that absolute path bypasses the prefix and
    // 404s. Strip the leading slash from a saved "/admin/state" so
    // existing users get the relative form without manual cleanup.
    if (st.endpoint === '/admin/state') {
      st.endpoint = 'admin/state';
    }

    ui.endpointInput.value = st.endpoint;
    ui.useMockInput.checked = st.useMock;
    highlightViewButton();

    // Hostname chip
    ui.hostname.textContent = `⌂ ${shortHostname()}`;

    // Endpoint input
    ui.endpointInput.addEventListener('change', () => {
      st.endpoint = ui.endpointInput.value.trim() || DEFAULT_ENDPOINT;
      savePrefs();
      // If the user just changed the endpoint, restart polling
      startPolling();
    });

    // Use-mock checkbox
    ui.useMockInput.addEventListener('change', () => {
      st.useMock = ui.useMockInput.checked;
      // Reset event dedupe so the new data source starts fresh
      st.seenEventKeys = new Set();
      st.pendingNewEvents = 0;
      hideTailPill();
      savePrefs();
      startPolling();
    });

    // View buttons
    for (const btn of ui.viewButtons) {
      btn.addEventListener('click', () => {
        st.view = btn.dataset.view;
        st.useMock = true;             // view buttons imply mock
        ui.useMockInput.checked = true;
        st.seenEventKeys = new Set();
        st.pendingNewEvents = 0;
        hideTailPill();
        highlightViewButton();
        savePrefs();
        startPolling();
      });
    }

    // Tail pill click: jump to bottom and reset pending count
    ui.tailPill.addEventListener('click', () => {
      const body = ui.bodies.activity;
      body.scrollTop = body.scrollHeight;
      hideTailPill();
    });
  }

  function highlightViewButton() {
    for (const btn of ui.viewButtons) {
      btn.classList.toggle('is-active', btn.dataset.view === st.view);
    }
  }

  function savePrefs() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        endpoint: st.endpoint,
        useMock:  st.useMock,
        view:     st.view,
      }));
    } catch (_) { /* ignore quota / private mode */ }
  }

  // ---------------------------------------------------------------- mock state

  // Generate a realistic /admin/state snapshot. Three views:
  //   healthy  - normal operation
  //   armed    - kill switch engaged (fail-closed)
  // (offline is faked by throwing in fetchState, not by returning a snapshot)

  function mockState(view) {
    const now = new Date();
    const isoNow = now.toISOString();
    const base = {
      v: 1,
      ts: isoNow,
      ca_mode: 'NODE_EXTRA_CA_CERTS',
      session_key_age_seconds: 3725 + (now.getTime() / 1000) % 100 | 0,
      last_upstream_ok_ts: new Date(now.getTime() - 2300).toISOString(),
      sse_parse_failures_15m: 0,
      health: {
        signer_key_readable: true,
        upstream_reachable: true,
        chain_intact: true,
        patterns_loaded: 33,
        patterns_min_required: 16,
      },
      patterns: {
        count: 33,
        breakdown: { base: 16, ext: 16, pem: 1 },
        hash: 'a1b2c3d4e5f67890fedcba9876543210',
        last_reload_ts: new Date(now.getTime() - 30 * 60 * 1000).toISOString(),
        min_required: 16,
      },
      map: { size: 142, capacity: 10000, ttl_seconds: 14400, eviction_policy: 'lru' },
      chain: {
        lines: 14201,
        checkpoints: 142,
        last_signed_ts: new Date(now.getTime() - 60 * 1000).toISOString(),
        last_checkpoint_root_hash: 'f7e6d5c4b3a2987654321fedcba0987',
        current_head_prev_hash: '9a8b7c6d5e4f3210fedcba9876543210',
        verify_status: 'ok',
      },
      counters_5m: {
        redactions_per_min: 24,
        top_types: [
          { type: 'AWS_ACCESS_KEY', count: 12 },
          { type: 'ANTHROPIC_KEY', count: 4 },
          { type: 'PEM_BLOCK',      count: 1 },
        ],
        latency_p50_ms: 14,
        latency_p99_ms: 87,
        unknown_placeholders: 0,
      },
      sessions: [
        { session_id: 'sess_xyz12345abcdef', redactions: 142,
          started_ts: new Date(now.getTime() - (4*3600 + 8*60) * 1000).toISOString() },
        { session_id: 'sess_pqr67890ghijkl', redactions: 23,
          started_ts: new Date(now.getTime() - 47 * 60 * 1000).toISOString() },
      ],
      recent_activity: makeMockActivity(now, view === 'armed'),
      verify_install: { checks_passed: 10, checks_total: 10, last_run_ts: new Date(now.getTime() - 3600*1000).toISOString() },
    };

    if (view === 'armed') {
      base.killswitch = {
        config: true, sigusr1: false, sentinel: false, http: true, active: true,
      };
      base.status = 'ok';  // process is alive, just blocking
      base.counters_5m.redactions_per_min = 0;
      base.counters_5m.top_types = [];
      base.counters_5m.unknown_placeholders = 0;
    } else {
      base.killswitch = {
        config: false, sigusr1: false, sentinel: false, http: false, active: false,
      };
      base.status = 'ok';
    }
    base.uptime_seconds = 15120 + Math.floor((now.getTime() / 1000) % 600);
    return base;
  }

  // Build a recent_activity list that "ticks" — each call increments the
  // tail, so a 1Hz poll against mock mode animates a real tail.
  let mockSeq = 0;
  function makeMockActivity(now, armed) {
    mockSeq++;
    // 18 historical events spread over the last ~60s
    const types = [
      ['AWS_KEY', 'ANTHROPIC_KEY', 'JWT'],
      ['AWS_KEY'],
      ['PEM_BLOCK'],
      ['GITHUB_TOKEN'],
      ['AWS_KEY', 'JWT'],
      ['ANTHROPIC_KEY'],
    ];
    const events = [];
    for (let i = 0; i < 18; i++) {
      const tOffsetMs = (18 - i) * 3500 + (mockSeq * 1000) % 3500;
      const t = new Date(now.getTime() - tOffsetMs);
      const ts = timeOnly(t.toISOString());
      const isOut = i % 3 !== 2;  // 2/3 OUT, 1/3 IN
      if (isOut) {
        const typesForEvent = types[i % types.length];
        const redactions = typesForEvent.length;
        events.push({
          ts,
          direction: 'OUT',
          request_id: `req_${String.fromCharCode(97 + (i % 6))}${(1000 + mockSeq * 7 + i * 13) % 9999}`,
          redactions,
          types: typesForEvent,
          blocked: armed,
        });
      } else {
        events.push({
          ts,
          direction: 'IN',
          request_id: `req_${String.fromCharCode(97 + ((i + 3) % 6))}${(1000 + mockSeq * 7 + i * 13) % 9999}`,
          detok_count: 0,
        });
      }
    }
    return events;
  }

  // ---------------------------------------------------------------- init

  document.addEventListener('DOMContentLoaded', () => {
    wireControls();
    startPolling();
  });
})();
