// Exercise actual risk rendering, safe text, stale responses and disposition submission.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this.textContent = ''; this.value = ''; }
  appendChild(child) { this.children.push(child); }
  get firstChild() { return this.children[0]; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  addEventListener(event, fn) { this.listeners[event] = fn; }
  set innerHTML(value) { throw Error('Source data must not become HTML'); }
}
function descendants(el) { return el.children.flatMap(row => [row, ...descendants(row)]); }
const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
const elements = {};
for (const match of html.matchAll(/id="([^"]+)"/g)) elements[match[1]] = new Element('div');
const malicious = '<img src=x onerror=DO_NOT_EXECUTE>';
const risk = {asset_id:'ai-1',cve_id:'CVE-2026-12345',asset:{name:malicious,product:'ollama',version:'1.0'},
  label:'待确认',priority:'补充信息',disposition:'pending',disposition_label:'待处理',status:'unknown',
  updated_at:'fixture',reason:malicious,fingerprint:'fixture-fingerprint',
  evidence:[{citation_id:'fixture',text:malicious,url:'javascript:DO_NOT_EXECUTE'}]};
const calls = [], errors = [], pending = [];
const context = {
  $: id => elements[id],
  clear: el => { el.children = []; },
  add: (parent,tag,cls,text) => { const el = new Element(tag); el.textContent = text || ''; parent.appendChild(el); return el; },
  on: (id,event,fn) => { assert.ok(elements[id], id); elements[id].addEventListener(event,fn); },
  showError: err => errors.push(err), showToast: () => {}, setView: () => {}, setInterval: () => {},
  formatStamp: value => 'local:' + value,
  api: (url,options) => {
    calls.push({url, options});
    if (url.startsWith('/api/risks?')) {
      if (pending.length) return pending.shift();
      return Promise.resolve({items:[risk],total:1});
    }
    if (url === '/api/investigations') return Promise.resolve({items:[],total:0,worker_enabled:true});
    return Promise.resolve(risk);
  }
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/risks.js'), 'utf8'), context);
async function main() {
  await context.loadRisks();
  const nodes = descendants(elements['risk-list']);
  assert.ok(nodes.some(row => row.textContent.includes(malicious)));
  assert.equal(nodes.filter(row => row.tag === 'a').length, 0, 'unsafe evidence URL must not be linked');
  const resolved = nodes.find(row => row.tag === 'option' && row.value === 'resolved');
  assert.equal(resolved.disabled, true, 'unknown risk must not be closed');
  const form = nodes.find(row => row.tag === 'form');
  form.listeners.input();
  await context.loadRisks();
  assert.equal(descendants(elements['risk-list']).find(row => row.tag === 'form'), form,
    'background refresh must preserve the form being edited');
  const select = nodes.find(row => row.tag === 'select');
  select.value = 'in_progress';
  form.listeners.submit({preventDefault() {}});
  await new Promise(resolve => setImmediate(resolve));
  const submission = calls.find(row => row.url.endsWith('/disposition'));
  assert.equal(JSON.parse(submission.options.body).expected_fingerprint, 'fixture-fingerprint');
  assert.equal(JSON.parse(submission.options.body).status, 'in_progress');
  let finishOld;
  pending.push(new Promise(resolve => { finishOld = resolve; }));
  const old = context.loadRisks();
  await context.loadRisks();
  finishOld({items:[],total:999}); await old;
  assert.ok(elements['risk-summary'].textContent.includes('1 条'), 'old response must not replace current results');
  const jobs = {worker_enabled:true,items:[{id:7,cve_id:'CVE-2026-12345',status:'done',attempts:1,context:{},trace:{}}]};
  context.renderInvestigations(jobs);
  const firstCard = elements['investigation-list'].children[0];
  firstCard.open = true;
  context.renderInvestigations(jobs);
  assert.equal(elements['investigation-list'].children[0], firstCard, 'unchanged poll must retain open trace and history');
  jobs.items.push({id:8,cve_id:'CVE-2026-12346',status:'pending',attempts:0,context:{},trace:{}});
  context.renderInvestigations(jobs);
  assert.equal(elements['investigation-list'].children[0].open, true, 'changed task list must retain expanded jobs by ID');
  assert.equal(errors.length, 0);
  console.log('risk UI regression checks passed');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
