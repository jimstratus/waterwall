// Quick test harness: loads webgui/app.js into a minimal jsdom-like shim
// and exercises wireControls + tick() once to verify no runtime errors.
const fs = require('fs');
const vm = require('vm');
const path = require('path');

// --------------------------------------------------------------- DOM shim
// A minimal DOM that supports the methods our app.js touches.
class ClassList {
  constructor() { this._set = new Set(); }
  add(c) { this._set.add(c); }
  remove(c) { this._set.delete(c); }
  toggle(c, force) {
    if (force === undefined) {
      if (this._set.has(c)) { this._set.delete(c); return false; }
      this._set.add(c); return true;
    }
    if (force) this._set.add(c); else this._set.delete(c);
    return force;
  }
  contains(c) { return this._set.has(c); }
  toString() { return [...this._set].join(' '); }
}

class El {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this._classes = new ClassList();
    this.dataset = {};
    this._innerHTML = '';
    this.style = {};
    this.attrs = {};
    this.scrollTop = 0;
    this.scrollHeight = 0;
    this.clientHeight = 0;
    this.hidden = false;
    this.textContent = '';
    this._listeners = {};
  }
  get className() { return this._classes.toString(); }
  set className(v) {
    this._classes = new ClassList();
    for (const c of String(v).split(/\s+/).filter(Boolean)) this._classes.add(c);
  }
  get classList() { return this._classes; }
  get innerHTML() { return this._innerHTML; }
  set innerHTML(v) { this._innerHTML = String(v); }
  addEventListener(ev, fn) {
    (this._listeners[ev] = this._listeners[ev] || []).push(fn);
  }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter(x => x !== c); return c; }
  querySelector(sel) {
    // Very limited: only "#id" supported
    if (sel.startsWith('#')) {
      const id = sel.slice(1);
      return document._byId[id] || null;
    }
    return null;
  }
  set textContent(v) { this._innerHTML = ''; this._textNode = String(v); }
  get textContent() { return this._textNode || this._innerHTML || ''; }
  set hidden(v) { this._hidden = !!v; }
  get hidden() { return this._hidden; }
}

function makeEl(tag, id) {
  const e = new El(tag);
  if (id) { e.id = id; document._byId[id] = e; }
  return e;
}

const document = {
  _byId: {},
  getElementById: (id) => document._byId[id] || null,
  querySelectorAll: (sel) => {
    if (sel === '.view-btn') return (document._viewBtns || []);
    return [];
  },
  addEventListener: (ev, fn) => {
    (document._listeners = document._listeners || {})[ev] = (document._listeners[ev] || []).concat(fn);
  },
  createElement: (tag) => new El(tag),
};

// Wire the expected DOM
makeEl('div', 'frame');
makeEl('span', 'hostname');
makeEl('span', 'status-chip');
makeEl('div', 'offline-banner');
makeEl('div', 'body-activity');
makeEl('div', 'body-counters');
makeEl('div', 'body-map-patterns');
makeEl('div', 'body-killswitch');
makeEl('div', 'body-chain');
makeEl('div', 'body-sessions');
makeEl('button', 'tail-pill');
makeEl('span', 'tail-pill-count');
const epIn = makeEl('input', 'endpoint-input');
epIn.value = 'http://127.0.0.1:8889/admin/state';
const mockIn = makeEl('input', 'use-mock');
mockIn.checked = true;
const pollInd = makeEl('span', 'poll-indicator');
makeEl('span', 'poll-dot');
makeEl('span', 'poll-text');
document._viewBtns = ['healthy', 'armed', 'offline'].map(v => {
  const b = makeEl('button', `view-${v}`);
  b.dataset = { view: v };
  return b;
});

// --------------------------------------------------------------- fetch shim
// Return a healthy mock state from any URL.
const mockJson = {
  v: 1,
  ts: new Date().toISOString(),
  status: 'ok',
  uptime_seconds: 15120,
  ca_mode: 'NODE_EXTRA_CA_CERTS',
  session_key_age_seconds: 3725,
  last_upstream_ok_ts: new Date().toISOString(),
  sse_parse_failures_15m: 0,
  health: { signer_key_readable: true, upstream_reachable: true, chain_intact: true, patterns_loaded: 33, patterns_min_required: 16 },
  killswitch: { config: false, sigusr1: false, sentinel: false, http: false, active: false },
  patterns: { count: 33, breakdown: { base: 16, ext: 16, pem: 1 }, hash: 'a1b2c3d4e5f67890fedcba9876543210', last_reload_ts: new Date().toISOString(), min_required: 16 },
  map: { size: 142, capacity: 10000, ttl_seconds: 14400, eviction_policy: 'lru' },
  chain: { lines: 14201, checkpoints: 142, last_signed_ts: new Date().toISOString(), last_checkpoint_root_hash: 'f7e6d5c4b3a2987654321fedcba0987', current_head_prev_hash: '9a8b7c6d5e4f3210fedcba9876543210', verify_status: 'ok' },
  counters_5m: { redactions_per_min: 24, top_types: [{type:'AWS_ACCESS_KEY',count:12},{type:'ANTHROPIC_KEY',count:4},{type:'PEM_BLOCK',count:1}], latency_p50_ms: 14, latency_p99_ms: 87, unknown_placeholders: 0 },
  sessions: [
    { session_id: 'sess_xyz12345abcdef', redactions: 142, started_ts: new Date(Date.now()-15000000).toISOString() },
  ],
  recent_activity: [
    { ts: '13:35:00.123', direction: 'OUT', request_id: 'req_abc', redactions: 3, types: ['AWS_KEY','ANTHROPIC_KEY','JWT'] },
    { ts: '13:35:00.987', direction: 'IN',  request_id: 'req_abc', detok_count: 0 },
  ],
  verify_install: { checks_passed: 10, checks_total: 10, last_run_ts: new Date().toISOString() },
};
class FakeResp {
  constructor(json, status=200) { this._json = json; this.status = status; }
  async json() { return this._json; }
}
const fetchImpl = async (url, opts) => {
  return new FakeResp(mockJson);
};
class AbortController { constructor() { this.signal = { aborted: false }; this._tid = null; } abort() { this.signal.aborted = true; if (this._tid) clearTimeout(this._tid); } }

// --------------------------------------------------------------- load + run
async function main() {
const code = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
const sandbox = {
  document,
  window: { hostname: 'test-host.local', location: { hostname: 'test-host.local' } },
  fetch: fetchImpl,
  AbortController,
  setInterval: (fn, ms) => { sandbox._intv = setInterval(fn, ms); return 1; },
  clearInterval: (id) => { if (sandbox._intv) clearInterval(sandbox._intv); },
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (id) => clearTimeout(id),
  localStorage: { getItem: () => null, setItem: () => {} },
  console,
};
sandbox.global = sandbox;
vm.createContext(sandbox);
try {
  vm.runInContext(code, sandbox);
  // Trigger DOMContentLoaded
  for (const fn of (document._listeners && document._listeners.DOMContentLoaded) || []) {
    fn();
  }
  // Tick has already run inside startPolling. Wait a tick for it to complete.
  await new Promise(r => setTimeout(r, 200));
  // Verify rendered content
  const counters = document.getElementById('body-counters').innerHTML;
  const ks       = document.getElementById('body-killswitch').innerHTML;
  const map      = document.getElementById('body-map-patterns').innerHTML;
  const chain    = document.getElementById('body-chain').innerHTML;
  const sessions = document.getElementById('body-sessions').innerHTML;
  const activity = document.getElementById('body-activity').innerHTML;
  const chip     = document.getElementById('status-chip').textContent;
  const frame    = document.getElementById('frame').classList;

  // Debug: print the activity HTML to diagnose the "req_abc" miss
  if (process.env.DEBUG) {
    console.log('--- body-activity HTML ---');
    console.log(activity.slice(0, 800));
    console.log('--- end ---');
  }

  const checks = [
    ['counters has "Redactions/min"', counters.includes('Redactions/min')],
    ['counters has "AWS_ACCESS_KEY"',   counters.includes('AWS_ACCESS_KEY')],
    ['ks shows DISARMED',               ks.includes('DISARMED')],
    ['ks shows http disarmed',          ks.includes('http') && ks.includes('disarmed')],
    ['map shows Map size',              map.includes('Map size')],
    ['map shows Policy hash',           map.includes('Policy hash')],
    ['map shows 16 base + 16 ext + 1 PEM', map.includes('16 base + 16 ext + 1 PEM')],
    ['chain shows Lines',               chain.includes('Lines')],
    ['chain shows Verify status: OK',   chain.includes('OK')],
    ['sessions has sess_xyz',           sessions.includes('sess_xyz')],
    ['activity has req_* id',         /req_[a-z0-9]+/.test(activity)],
    ['activity has AWS_KEY pill',      activity.includes('AWS_KEY')],
    ['activity has OUT row',           activity.includes('activity-out')],
    ['activity has IN row',            activity.includes('activity-in')],
    ['status chip UP',                  chip.includes('UP')],
    ['frame not offline',               !frame.contains('is-offline')],
    // migration: default endpoint is now relative (no leading slash)
    ['endpoint input has relative default', document.getElementById('endpoint-input').value === 'admin/state'],
  ];

  let pass = 0, fail = 0;
  for (const [name, ok] of checks) {
    console.log(`  ${ok ? '✓' : '✗'}  ${name}`);
    ok ? pass++ : fail++;
  }
  console.log(`\n  ${pass} pass, ${fail} fail`);
  // Cleanly stop the polling loop so node can exit
  if (sandbox._intv) clearInterval(sandbox._intv);
  if (fail > 0) process.exit(1);
  process.exit(0);
} catch (e) {
  console.error('RUNTIME ERROR:', e.message);
  console.error(e.stack);
  process.exit(1);
}
}

main().catch(e => { console.error(e); process.exit(1); });
