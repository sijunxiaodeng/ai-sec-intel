// Exercise actual risk rendering, safe text, stale responses and disposition submission.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this.textContent = ''; this.value = ''; this.dataset = {}; }
  appendChild(child) { return this.insertBefore(child,null); }
  insertBefore(child,before) { if(child.parentNode) child.parentNode.removeChild(child); const index=before ? this.children.indexOf(before) : this.children.length; this.children.splice(index,0,child); child.parentNode=this; return child; }
  get firstChild() { return this.children[0]; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); child.parentNode=null; }
  addEventListener(event, fn) { this.listeners[event] = fn; }
  setAttribute(key,value) { this[key]=value; }
  querySelector(selector) { return descendants(this).find(el=>el.tag==='details' && (selector!=='details[open]' || el.open)); }
  set innerHTML(value) { throw Error('Source data must not become HTML'); }
}
function descendants(el) { return el.children.flatMap(row => [row, ...descendants(row)]); }
const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
const elements = {};
for (const match of html.matchAll(/id="([^"]+)"/g)) elements[match[1]] = new Element('div');
const malicious = '<img src=x onerror=DO_NOT_EXECUTE>';
const risk = {asset_id:'ai-1',cve_id:'CVE-2026-12345',asset:{name:malicious,vendor:'ollama',product:'ollama',version:'1.0'},
  label:'待确认',priority:'补充信息',disposition:'pending',disposition_label:'待处理',status:'unknown',
  updated_at:'fixture',reason:malicious,fingerprint:'fixture-fingerprint',
  evidence:[{citation_id:'fixture',text:malicious,url:'javascript:DO_NOT_EXECUTE'}]};
const calls = [], errors = [], pending = [];
let riskRows=[risk], cveFailure=null;
const group={asset_id:'ai-1',asset:risk.asset,counts:{matched_version:0,unknown:1,not_matched:0,invalidated:0},total_cves:1,matching_cves:1,revision:'fixture'};
let componentResponse={items:[group],total:1,inventory_total:1,risk_total:1};
const investigationReplies = new Map();
let taskResponse = {items:[],total:0,worker_enabled:true};
let historyResponse = {items:[]};
const context = {
  $: id => elements[id],
  document: {createElement:tag=>new Element(tag)},
  clear: el => { el.children.forEach(child=>child.parentNode=null); el.children = []; },
  add: (parent,tag,cls,text) => { const el = new Element(tag); el.textContent = text || ''; parent.appendChild(el); return el; },
  on: (id,event,fn) => { assert.ok(elements[id], id); elements[id].addEventListener(event,fn); },
  showError: err => errors.push(err), showToast: () => {}, setView: () => {}, setInterval: () => {},
  formatStamp: value => 'local:' + value,
  api: (url,options) => {
    calls.push({url, options});
    if (url.startsWith('/api/risks/assets?')) {
      if (pending.length) return pending.shift();
      return Promise.resolve(componentResponse);
    }
    if (url.startsWith('/api/risks?')) {
      if(cveFailure) return Promise.reject(cveFailure);
      const offset=Number(new URL(url,'http://local').searchParams.get('offset'));
      return Promise.resolve({items:riskRows.slice(offset,offset+20),total:riskRows.length});
    }
    if (url.startsWith('/api/investigations?')) return Promise.resolve({...taskResponse, offset:Number(new URL(url, 'http://local').searchParams.get('offset'))});
    if (url.startsWith('/api/investigations/') && url.endsWith('/runs')) return Promise.resolve(historyResponse);
    if (url.startsWith('/api/investigations/') && options && options.method === 'POST') {
      const result = investigationReplies.get(url.slice('/api/investigations/'.length));
      return result instanceof Error ? Promise.reject(result) : Promise.resolve(result || {queued:1});
    }
    return Promise.resolve(risk);
  }
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/risks.js'), 'utf8'), context);
async function main() {
  await context.loadRisks();
  const component=elements['risk-list'].children[0];
  assert.equal(component.tag,'details','the first level must be a component');
  assert.equal(descendants(component).some(row=>row.tag==='h3'),false,'CVE rows must wait for the component to be opened');
  assert.equal(calls.some(row=>row.url.startsWith('/api/risks?')),false,'collapsed components must not download CVE pages');
  component.open=true; component.listeners.toggle();
  await new Promise(resolve=>setImmediate(resolve));
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
  assert.equal(elements['risk-list'].children[0],component,'polling must retain the component DOM and expanded state');
  assert.equal(component.open,true);
  riskRows=Array.from({length:21},(_,i)=>({...risk,cve_id:'CVE-2026-'+(12345+i)}));
  group.total_cves=21; group.matching_cves=21; group.counts.unknown=21; group.revision='many';
  await context.loadRisks();
  const view=context.riskAssetViews['ai-1'];
  assert.equal(view.next.disabled,false,'CVE pagination belongs to this component');
  view.next.listeners.click(); await new Promise(resolve=>setImmediate(resolve));
  assert.ok(calls.some(row=>row.url.includes('asset_id=ai-1') && row.url.endsWith('&limit=20&offset=20')));
  assert.equal(view.rows.children.length,1);
  await context.loadRisks(); assert.equal(view.offset,20,'polling must preserve the component CVE page');
  view.prev.listeners.click(); await new Promise(resolve=>setImmediate(resolve));
  assert.equal(view.offset,0);
  cveFailure=Error('temporary fixture failure'); group.revision='failed-read';
  await context.loadRisks();
  assert.equal(view.retry.hidden,false);
  assert.ok(view.message.textContent.includes('保留上次结果'));
  cveFailure=null; view.retry.listeners.click(); await new Promise(resolve=>setImmediate(resolve));
  assert.equal(view.retry.hidden,true);
  let finishOld;
  pending.push(new Promise(resolve => { finishOld = resolve; }));
  const old = context.loadRisks();
  await context.loadRisks();
  finishOld({items:[],total:999,inventory_total:999,risk_total:999}); await old;
  assert.ok(elements['risk-summary'].textContent.includes('1 个组件'), 'old response must not replace current results');
  componentResponse={items:[{asset_id:'empty',asset:{name:'No decisions',vendor:'vllm',product:'vllm',version:'1'},counts:{matched_version:0,unknown:0,not_matched:0,invalidated:0},total_cves:0,revision:'empty'}],total:1,inventory_total:1,risk_total:0};
  riskRows=[];
  await context.loadRisks();
  const empty=elements['risk-list'].children[0]; empty.open=true; empty.listeners.toggle();
  await new Promise(resolve=>setImmediate(resolve));
  assert.ok(context.riskAssetViews.empty.message.textContent.includes('不能据此判断资产安全'));
  componentResponse={items:[group],total:1,inventory_total:1,risk_total:21}; riskRows=[risk];
  const jobs = {worker_enabled:true,total:65,offset:0,items:[{id:7,cve_id:'CVE-2026-12345',status:'done',attempts:1,context:{},trace:{calls:[{tool:'epss',status:'success',duration_ms:10}],model_calls:2}}]};
  context.renderInvestigations(jobs);
  const firstCard = elements['investigation-list'].children[0];
  firstCard.open = true;
  context.renderInvestigations(jobs);
  assert.equal(elements['investigation-list'].children[0], firstCard, 'unchanged poll must retain open trace and history');
  historyResponse = {items:[{run_id:'saved-run-7',status:'done',trace:{stop_reason:'evidence_sufficient'}}]};
  descendants(firstCard).find(row => row.tag === 'button').listeners.click();
  await new Promise(resolve => setImmediate(resolve));
  const savedHistory = descendants(firstCard).find(row => row.textContent.includes('saved-run-7'));
  assert.ok(savedHistory, 'history must be loaded before polling');
  jobs.worker = {configured_enabled:true,status:'running',background:{running:true,last_started_at:10,last_finished_at:11},explicit:{running:true,last_started_at:12,last_finished_at:13}};
  context.renderInvestigations(jobs);
  jobs.worker.explicit.last_started_at = 14;
  jobs.worker.explicit.last_finished_at = 15;
  context.renderInvestigations(jobs);
  assert.equal(elements['investigation-list'].children[0], firstCard, 'heartbeat changes must preserve task DOM');
  assert.equal(firstCard.open, true, 'heartbeat changes must preserve expanded details');
  assert.ok(descendants(firstCard).includes(savedHistory), 'heartbeat changes must preserve loaded execution history');
  jobs.worker.status = 'partial';
  jobs.worker.background.running = false;
  context.renderInvestigations(jobs);
  assert.match(elements['investigation-worker'].textContent, /部分后台线程未运行.*资产自动研判：未运行.*主动研判：运行中/);
  assert.equal(elements['investigation-list'].children[0], firstCard, 'worker banner changes need not replace unchanged tasks');
  assert.ok(descendants(firstCard).includes(savedHistory));
  historyResponse = {items:[]};
  jobs.items.push({id:8,cve_id:'CVE-2026-12346',status:'pending',attempts:0,context:{},trace:{}});
  context.renderInvestigations(jobs);
  assert.equal(elements['investigation-list'].children[0].open, true, 'changed task list must retain expanded jobs by ID');
  let taskNodes = descendants(elements['investigation-list']);
  assert.ok(taskNodes.some(row => row.textContent.includes('任务执行 0 次')));
  assert.ok(taskNodes.some(row => row.textContent.includes('最近已保存轨迹：工具调用 1 次 · 模型调用 2 次')), 'queue attempts and saved agent calls must be separate');
  const retryingJob = {...jobs.items[0], status:'running', attempts:2, wait_reason:{code:'execution_unconfirmed',label:'线程未运行，保留执行标记'}};
  context.renderInvestigations({worker_enabled:true,total:1,items:[retryingJob]});
  let runningNodes = descendants(elements['investigation-list']);
  assert.ok(runningNodes.some(row => row.tag === 'summary' && row.textContent.includes('保留执行标记')));
  assert.ok(runningNodes.some(row => row.textContent.includes('最近已保存轨迹：工具调用 1 次')), 'retry must not relabel previous trace as current');
  assert.equal(runningNodes.filter(row => row.textContent.includes('当前执行的 Agent 轨迹将在执行结束后保存')).length, 1, 'running job explains pending trace exactly once');
  retryingJob.trace = {};
  retryingJob.wait_reason = {code:'execution_stopping',label:'线程正在停止'};
  context.renderInvestigations({worker_enabled:true,total:1,items:[retryingJob]});
  runningNodes = descendants(elements['investigation-list']);
  assert.ok(runningNodes.some(row => row.tag === 'summary' && row.textContent.includes('停止中（保留执行标记）')));
  assert.equal(runningNodes.filter(row => row.textContent.includes('当前执行的 Agent 轨迹将在执行结束后保存')).length, 1, 'running job without old trace also explains pending trace once');
  context.renderInvestigations(jobs);
  assert.ok(elements['investigation-summary'].textContent.includes('65 项'));
  assert.equal(elements['investigation-next'].disabled, false);
  elements['investigation-next'].listeners.click();
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(calls.some(row => row.url === '/api/investigations?limit=30&offset=30'), 'task pagination must request subsequent pages');
  elements['investigation-prev'].listeners.click();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(context.investigationOffset, 0);

  const disabledJob = {id:9,cve_id:'CVE-2026-12347',status:'pending',attempts:0,context:{reason:'assets_changed'},trace:{},wait_reason:{code:'worker_disabled',label:'当前实例后台处理关闭'}};
  context.renderInvestigations({worker_enabled:false,worker:{configured_enabled:false,status:'disabled',background:{running:false},explicit:{running:false}},total:1,items:[disabledJob]});
  assert.match(elements['investigation-worker'].textContent, /部署配置中开启采集后自动研判.*重启/);
  taskNodes = descendants(elements['investigation-list']);
  assert.ok(taskNodes.some(row => row.textContent.includes('当前实例后台处理关闭')));
  const historyButton = taskNodes.find(row => row.tag === 'button');
  historyButton.listeners.click();
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(descendants(elements['investigation-list']).some(row => row.textContent.includes('暂无已保存的执行记录')));
  context.renderInvestigations({worker_enabled:true,worker:{configured_enabled:true,status:'not_started',background:{running:false},explicit:{running:false},restart_required:true},total:1,items:[disabledJob]});
  assert.match(elements['investigation-worker'].textContent, /线程尚未启动/);
  assert.doesNotMatch(elements['investigation-worker'].textContent, /后台处理正在运行/);
  disabledJob.wait_reason = {code:'prerequisites',label:'等待资料抓取',prerequisites:[{stage:'documents',status:'pending',attempts:0}]};
  context.renderInvestigations({worker_enabled:true,total:1,items:[disabledJob]});
  assert.ok(descendants(elements['investigation-list']).some(row => row.textContent.includes('前置任务：资料抓取')));

  assert.deepEqual(Array.from(context.parseInvestigationCves('cve-2024-37032, CVE-2025-0312\nCVE-2024-37032，CVE-2026-12345')), ['CVE-2024-37032','CVE-2025-0312','CVE-2026-12345']);
  assert.throws(() => context.parseInvestigationCves('CVE-2024-37032 <script>'), /格式有误/);
  assert.throws(() => context.parseInvestigationCves(''), /至少一个/);
  assert.throws(() => context.parseInvestigationCves(Array.from({length:21}, (_,i) => 'CVE-2026-' + (10000+i)).join(',')), /最多研究 20/);
  const submit = elements['investigation-form'].listeners.submit;
  const event = {preventDefault(){}};
  elements['investigation-cve'].value = 'CVE-2024-37032 bad';
  const beforeInvalid = calls.length;
  await submit(event);
  assert.equal(calls.length, beforeInvalid, 'validate all IDs before queuing any task');

  investigationReplies.set('CVE-2025-0312', new Error('知识库中没有这条情报'));
  elements['investigation-cve'].value = 'cve-2024-37032, CVE-2025-0312\nCVE-2024-37032';
  await submit(event);
  const posts = calls.filter(row => row.options && row.options.method === 'POST' && row.url.startsWith('/api/investigations/'));
  assert.deepEqual(posts.map(row => row.url), ['/api/investigations/CVE-2024-37032','/api/investigations/CVE-2025-0312'], 'deduplicate IDs and send individual requests');
  assert.equal(elements['investigation-cve'].value, 'CVE-2025-0312', 'retain only unconfirmed IDs for retry');
  assert.ok(descendants(elements['investigation-submission']).some(row => row.textContent.includes('已排队 1 项') && row.textContent.includes('提交未确认 1 项')));
  assert.equal(elements['investigation-submit'].disabled, false);
  assert.equal(elements['investigation-cve'].disabled, false);

  let finishBatch;
  investigationReplies.set('CVE-2026-12348', new Promise(resolve => { finishBatch = resolve; }));
  elements['investigation-cve'].value = 'CVE-2026-12348';
  const firstSubmission = submit(event);
  await submit(event);
  assert.equal(calls.filter(row => row.url === '/api/investigations/CVE-2026-12348').length, 1, 'double submit must not enqueue twice');
  finishBatch({queued:1}); await firstSubmission;
  assert.equal(elements['investigation-cve'].value, '');
  assert.equal(errors.length, 0);
  console.log('risk UI regression checks passed');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
