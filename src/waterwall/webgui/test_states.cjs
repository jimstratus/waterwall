// Test ARMED + OFFLINE view modes.
const fs = require('fs');
const path = require('path');
const vm = require('vm');

class ClassList {
  constructor() { this._set = new Set(); }
  add(c) { this._set.add(c); }
  remove(c) { this._set.delete(c); }
  contains(c) { return this._set.has(c); }
  toggle(c, force) {
    if (force === undefined) {
      if (this._set.has(c)) { this._set.delete(c); return false; }
      this._set.add(c); return true;
    }
    if (force) this._set.add(c); else this._set.delete(c);
    return force;
  }
  toString() { return [...this._set].join(' '); }
}

class El {
  constructor(tag='div') {
    this.tagName=tag.toUpperCase(); this.children=[]; this._classes=new ClassList();
    this.dataset={}; this._innerHTML=''; this.style={}; this.attrs={};
    this.scrollTop=0; this.scrollHeight=0; this.clientHeight=0; this.hidden=false;
    this._listeners={};
  }
  get className() { return this._classes.toString(); }
  set className(v) { this._classes=new ClassList(); for (const c of String(v).split(/\s+/).filter(Boolean)) this._classes.add(c); }
  get classList() { return this._classes; }
  get innerHTML() { return this._innerHTML; }
  set innerHTML(v) { this._innerHTML=String(v); }
  addEventListener(ev,fn) { (this._listeners[ev]=this._listeners[ev]||[]).push(fn); }
  set textContent(v) { this._innerHTML=''; this._textNode=String(v); }
  get textContent() { return this._textNode||this._innerHTML||''; }
  set hidden(v) { this._hidden=!!v; } get hidden() { return this._hidden; }
}

const document = { _byId:{}, _viewBtns:[], _listeners:{} };
document.getElementById = (id) => document._byId[id] || null;
document.querySelectorAll = (sel) => sel==='.view-btn' ? document._viewBtns : [];
document.addEventListener = (ev,fn) => { (document._listeners[ev]=document._listeners[ev]||[]).push(fn); };
const makeEl = (tag,id) => { const e=new El(tag); if(id){e.id=id; document._byId[id]=e;} return e; };

for (const id of ['frame','hostname','status-chip','offline-banner','body-activity','body-counters','body-map-patterns','body-killswitch','body-chain','body-sessions','tail-pill','tail-pill-count','poll-indicator','poll-dot','poll-text'])
  makeEl('div', id);
makeEl('input','endpoint-input').value = 'http://127.0.0.1:8889/admin/state';
const mockIn = makeEl('input','use-mock'); mockIn.checked = true;
for (const v of ['healthy','armed','offline']) {
  const b = makeEl('button', `view-${v}`); b.dataset={view:v}; document._viewBtns.push(b);
}

const fetchImpl = async () => { throw new Error('fetch should not be called when useMock=true'); };
class AbortController { constructor() { this.signal={aborted:false}; } abort(){this.signal.aborted=true;} }

async function main() {
  const code = fs.readFileSync(path.join(__dirname, 'app.js'),'utf8');
  const sandbox = {
    document, window:{hostname:'test-host',location:{hostname:'test-host'}},
    fetch: fetchImpl, AbortController,
    setInterval: (fn,ms) => { sandbox._intv=setInterval(fn,ms); return 1; },
    clearInterval: ()=>{ if(sandbox._intv){clearInterval(sandbox._intv);sandbox._intv=null;} },
    setTimeout: (fn,ms)=>setTimeout(fn,ms), clearTimeout: (id)=>clearTimeout(id),
    localStorage: { getItem:()=>null, setItem:()=>{} }, console,
  };
  sandbox.global = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox);
  for (const fn of (document._listeners.DOMContentLoaded||[])) fn();
  await new Promise(r=>setTimeout(r,200));

  // ----- ARMED -----
  const armedBtn = document._viewBtns.find(b => b.dataset.view === 'armed');
  for (const fn of (armedBtn._listeners.click||[])) fn();
  await new Promise(r=>setTimeout(r,200));
  const ksArmed = document.getElementById('body-killswitch').innerHTML;
  const chipArmed = document.getElementById('status-chip').textContent;
  const armedChecks = [
    ['ARMED banner present', ksArmed.includes('ARMED')],
    ['BLOCKING ALL TRAFFIC', ksArmed.includes('BLOCKING ALL TRAFFIC')],
    ['Asserted by: present', ksArmed.includes('Asserted by:')],
    ['status chip still UP (process alive)', chipArmed.includes('UP')],
    ['frame not offline (armed != offline)', !document.getElementById('frame').classList.contains('is-offline')],
  ];

  // ----- OFFLINE -----
  const offBtn = document._viewBtns.find(b => b.dataset.view === 'offline');
  for (const fn of (offBtn._listeners.click||[])) fn();
  await new Promise(r=>setTimeout(r,200));
  const offBanner = document.getElementById('offline-banner').textContent;
  const chipOff = document.getElementById('status-chip').textContent;
  const offChecks = [
    ['offline banner shows PROXY OFFLINE', offBanner.includes('PROXY OFFLINE')],
    ['offline banner shows verify-install hint', offBanner.includes('verify-install')],
    ['status chip OFFLINE', chipOff.includes('OFFLINE')],
    ['frame is-offline class', document.getElementById('frame').classList.contains('is-offline')],
    ['counters body shows "proxy offline"', document.getElementById('body-counters').innerHTML.includes('proxy offline')],
  ];

  let pass=0, fail=0;
  console.log('--- ARMED ---');
  for (const [n,ok] of armedChecks) { console.log(`  ${ok?'✓':'✗'}  ${n}`); ok?pass++:fail++; }
  console.log('--- OFFLINE ---');
  for (const [n,ok] of offChecks) { console.log(`  ${ok?'✓':'✗'}  ${n}`); ok?pass++:fail++; }
  console.log(`\n  ${pass} pass, ${fail} fail`);
  if (sandbox._intv) clearInterval(sandbox._intv);
  process.exit(fail?1:0);
}
main().catch(e=>{console.error(e);process.exit(1);});
