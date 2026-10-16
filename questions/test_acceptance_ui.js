// Exercise the actual acceptance renderer and conflict flow, not copied markup logic.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this.textContent = ''; this.value = ''; this.style = {}; this.attrs = {}; this.hidden = false; this.files = []; }
  appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
  get firstChild() { return this.children[0]; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  addEventListener(event, fn) { this.listeners[event] = fn; }
  setAttribute(key, value) { this.attrs[key] = value; }
  querySelectorAll(selector) { return descendants(this).filter(el => selector === 'button[type=submit]' && el.tag === 'button' && el.type === 'submit'); }
  scrollIntoView() {}
  set innerHTML(value) { throw Error('External acceptance data must never become HTML'); }
}
function descendants(el) { return el.children.flatMap(row => [row, ...descendants(row)]); }
function texts(el) { return [el, ...descendants(el)].map(node => node.textContent).join('\n'); }
const elements = {};
const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
for (const match of html.matchAll(/id="([^"]+)"/g)) elements[match[1]] = new Element('div');
elements['ac-case-filter'].value = 'all';
const malicious = '<img src=x onerror=DO_NOT_EXECUTE>';
const group = {cases: 2, reviewed_cases: 0, unreviewed_cases: 2, independent_reviewed_cases: 0, independent_accuracy: null, independent_denominator: 0, reviewed_subset_accuracy: null, reviewed_subset_denominator: 0, independent_blockers: [malicious]};
const fixtureRun = {run_id: 'run-1', title: malicious, model: malicious, run_at: '2026-10-15T03:00:00Z', dataset_visibility: 'public_development', evaluation_unit: 'case', dataset_sha256: 'a'.repeat(64), statistics: {automatic_passed: 1, automatic_failed: 1, automatic_unchecked: 0, by_kind: {basic: group, multi_hop: group, enrichment: {cases: 0}}}, cases: [
  {id: 'Q01', question: malicious, prediction: malicious, reference: 'ref', context: {url: 'javascript:DO_NOT_EXECUTE', text: malicious}, revision: 0, automatic_passed: false, reasoning_kind: 'multi_hop', review_history: []},
  {id: 'Q02', question: 'another', prediction: 'answer', revision: 0, automatic_passed: true, latest_review: null, review_history: []}
]};
const threshold = {collected: 0, late: 1, missing: 2, unknown: 3, not_due: 4, excluded: 5, denominator: 3, within_rate: 0};
const windowRecord = {id: 'window-1', name: 'real', status: 'active', start_at: '2026-10-15T00:00:00Z', end_at: '2026-10-18T00:00:00Z', latest_snapshot_at: '2026-10-16T12:00:00Z', snapshots_count: 1, sources: [malicious], scope: malicious, metrics: {observed: {record_count: 0, eligible_count: 0, latency: {}, by_threshold: {'6': threshold}}, inventory: {inventory_count: 0, recall: null}}, coverage: {source_run_history: [{source: malicious, runs: 1, success: 0, partial: 1, failed: 0}]}};
const summary = {generated_at: '2026-10-15T03:00:00Z', criteria: [{title: malicious, weight: 15, target: malicious, observed: malicious, status: 'pending', view: 'quality'}], quality_runs: [fixtureRun], observation_windows: [windowRecord], evidence: [{id: 'safe-id', title: malicious, filename: malicious, available: true, download_url: 'javascript:DO_NOT_EXECUTE'}], runtime: {}, method: [malicious]};
let reviewStatus = 409, currentRevision = 0, pendingReview = null;
const calls = [], pendingRuns = [];
const context = {
  $: id => elements[id], clear: el => { el.children = []; },
  add: (parent, tag, cls, text) => { const el = new Element(tag); el.className = cls || ''; el.textContent = text == null ? '' : String(text); parent.appendChild(el); return el; },
  on: (id, event, fn) => { assert.ok(elements[id], id); elements[id].addEventListener(event, fn); },
  formatStamp: value => '北京时间:' + value, setView() {},
  fetch: (url, options) => {
    calls.push({url, options});
    let status = 200, body;
    if (url === '/api/acceptance/summary') body = summary;
    else if (url.includes('/reviews/')) { if (pendingReview) { const pending = pendingReview; pendingReview = null; return pending; } status = reviewStatus; body = status === 409 ? {detail: 'review revision conflict'} : {revision: 2}; }
    else if (url === '/api/acceptance/quality/run-1') {
      if (pendingRuns.length) return pendingRuns.shift();
      body = JSON.parse(JSON.stringify(fixtureRun)); body.cases[0].revision = currentRevision;
      if (currentRevision) body.cases[0].latest_review = {revision: currentRevision, reviewer: 'new reviewer', correct: false, reasoning_kind: 'multi_hop'};
    } else if (url === '/api/acceptance/observations/window-1') body = windowRecord;
    else if (url === '/api/acceptance/observations') body = windowRecord;
    else body = {};
    return Promise.resolve({ok: status < 400, status, json: () => Promise.resolve(body)});
  }
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/acceptance.js'), 'utf8'), context);
const flush = () => new Promise(resolve => setImmediate(resolve));
async function main() {
  // Product nav must not expose the scoring/acceptance wall; page markup may remain for ops.
  assert.doesNotMatch(html, /data-view="acceptance"/);
  assert.match(html, /id="acceptance"/);
  await context.loadAcceptance();
  assert.match(texts(elements['ac-criteria']), /DO_NOT_EXECUTE/);
  assert.match(texts(elements['ac-case-detail']), /DO_NOT_EXECUTE/);
  assert.equal(context.acRate(null), '待验证');
  assert.equal(context.acRate(0), '0.0%');
  assert.equal(context.acCount(null), '未知');
  assert.match(texts(elements['ac-quality-summary']), /公开开发集/);
  assert.match(texts(elements['ac-quality-summary']), /按声明独立复核准确率/);
  assert.match(texts(elements['ac-quality-summary']), /明确多跳问答/);
  assert.match(texts(elements['ac-quality-summary']), /比较或普通多轮追问不自动算多跳/);
  assert.doesNotMatch(texts(elements['ac-quality-summary']), /富化事实\n/);
  const originalRun = context.acceptanceState.run;
  context.acceptanceState.run = {...originalRun, statistics: {...originalRun.statistics, by_kind: {
    basic: {...group, reviewed_cases: 2, independent_accuracy: 0.5, independent_blockers: []},
    multi_hop: {cases: 0}, enrichment: {cases: 0}
  }}};
  context.acRenderQuality();
  assert.match(texts(elements['ac-quality-summary']), /基础问答\n50.0%/);
  assert.doesNotMatch(texts(elements['ac-quality-summary']), /明确多跳问答|富化事实\n|无多跳样本|比较或普通多轮追问/);
  context.acceptanceState.run.statistics.by_kind.enrichment = group;
  context.acRenderQuality();
  assert.match(texts(elements['ac-quality-summary']), /富化事实\n待验证/, 'existing samples must retain their actual review state');
  context.acceptanceState.run.statistics.by_kind.enrichment = {...group,
    reviewed_subset_by_reviewer_type:{ai:2,human:0}, reviewed_subset_accuracy:0.5,
    reviewed_subset_denominator:2,reviewed_subset_passed:1};
  context.acRenderQuality();
  assert.match(texts(elements['ac-quality-summary']), /富化事实\n50.0%/);
  assert.match(texts(elements['ac-quality-summary']), /AI辅助复核通过比例（非独立人审）/);
  context.acceptanceState.run = originalRun;
  context.acRenderQuality();
  assert.match(texts(elements['ac-quality-summary']), /评测代码提交\n未登记（版本未知）/);
  context.acceptanceState.run.source_commit = 'a'.repeat(40); context.acRenderQuality();
  assert.match(texts(elements['ac-quality-summary']), new RegExp('评测代码提交\\na{40}'));
  const links = descendants(elements['ac-evidence-list']).filter(el => el.tag === 'a');
  assert.equal(links.length, 1);
  assert.equal(links[0].href, '/api/acceptance/evidence/safe-id/download', 'download must use registered ID, never arbitrary response URL');
  assert.equal(descendants(elements['ac-case-detail']).filter(el => el.tag === 'a').length, 0, 'source text cannot inject URL anchors');
  assert.equal(context.acProgress(windowRecord), 50, 'timeline uses saved snapshot, not browser clock');
  assert.equal(context.acProgress({...windowRecord, latest_snapshot_at: null}), 0);
  assert.match(texts(elements['ac-observation-detail']), /尚无上游清单/);
  assert.match(texts(elements['ac-observation-detail']), /尚未到期 4/);
  assert.match(texts(elements['ac-observation-detail']), /到期未采 2/);
  assert.match(texts(elements['ac-observation-detail']), /初始部署版本\n未登记（版本未知）/);
  context.acceptanceState.window.source_commit = 'b'.repeat(40);
  context.acceptanceState.window.versions_seen = ['b'.repeat(40), 'c'.repeat(40), null]; context.acRenderWindow();
  assert.match(texts(elements['ac-observation-detail']), new RegExp('观察中见过版本\\nb{40}；c{40}；未登记（版本未知）'));
  assert.equal(descendants(elements['ac-observation-detail']).find(el => el.tag === 'button' && el.textContent === '冻结观察报告').disabled, true);
  const sampleParent = new Element('div');
  context.acSampleDetails(sampleParent, 'sample records', Array.from({length: 25}, (_, index) => ({source: malicious, id: 'RECORD-' + String(index).padStart(3, '0'), published_at: null, first_seen_at: null, delay_seconds: null, thresholds: {'6': 'unknown'}})));
  assert.match(texts(sampleParent), /RECORD-019/);
  assert.doesNotMatch(texts(sampleParent), /RECORD-020/);
  descendants(sampleParent).find(el => el.tag === 'button' && el.textContent === '下一页').listeners.click();
  assert.match(texts(sampleParent), /RECORD-024/);
  const sampleSearch = descendants(sampleParent).find(el => el.tag === 'input');
  sampleSearch.value = 'RECORD-003'; sampleSearch.listeners.input();
  assert.match(texts(sampleParent), /RECORD-003/);
  assert.doesNotMatch(texts(sampleParent), /RECORD-024/);

  let nodes = descendants(elements['ac-case-detail']);
  const form = nodes.find(el => el.tag === 'form');
  const reviewer = nodes.find(el => el.tag === 'input' && el.type === 'text'); reviewer.value = malicious;
  const selects = nodes.filter(el => el.tag === 'select');
  assert.equal(selects[1].value, 'multi_hop');
  assert.equal(selects[1].disabled, true, 'frozen reasoning category cannot be relabeled');
  selects[2].value = 'yes'; selects[3].value = 'no'; selects[4].value = ''; selects[5].value = 'yes';
  nodes.find(el => el.tag === 'textarea').value = 'keep my draft';
  form.listeners.input();
  form.listeners.submit({preventDefault() {}}); await flush();
  let submissions = calls.filter(row => row.url.includes('/reviews/'));
  let payload = JSON.parse(submissions[0].options.body);
  assert.equal(payload.expected_revision, 0);
  assert.equal(payload.correct, true);
  assert.equal(payload.citations_supported, false);
  assert.equal(payload.conditions_preserved, null, 'unchecked must remain null, not false or true');
  assert.match(texts(form), /版本冲突/);
  assert.equal(nodes.find(el => el.tag === 'textarea').value, 'keep my draft');
  assert.equal(submissions.length, 1, 'conflict must not retry or overwrite automatically');
  currentRevision = 1;
  const resolve = nodes.find(el => el.tag === 'button' && el.textContent === '查看最新复核并更新草稿版本');
  resolve.listeners.click(); await flush();
  assert.match(texts(elements['ac-case-detail']), /new reviewer/);
  form.listeners.submit({preventDefault() {}}); await flush();
  submissions = calls.filter(row => row.url.includes('/reviews/'));
  payload = JSON.parse(submissions[1].options.body);
  assert.equal(payload.expected_revision, 1, 'explicit conflict resolution carries the current revision');
  assert.equal(payload.note, 'keep my draft');

  await context.acLoadRun('run-1');
  nodes = descendants(elements['ac-case-detail']);
  assert.equal(nodes.find(el => el.tag === 'textarea').value, 'keep my draft', 'refresh must preserve unsaved draft');
  let finishReview;
  pendingReview = new Promise(resolve => { finishReview = resolve; });
  const pendingForm = nodes.find(el => el.tag === 'form');
  pendingForm.listeners.submit({preventDefault() {}});
  nodes.find(el => el.tag === 'textarea').value = 'newer typing while saving';
  pendingForm.listeners.input();
  currentRevision = 2;
  finishReview({ok: true, status: 200, json: () => Promise.resolve({revision: 2})}); await flush();
  assert.equal(descendants(elements['ac-case-detail']).find(el => el.tag === 'textarea').value, 'newer typing while saving', 'successful request must not erase subsequent typing');
  elements['ac-case-filter'].value = 'automatic_failed'; context.acRenderCases();
  assert.equal(elements['ac-case-list'].children.length, 1);
  assert.equal(context.acCaseMatches(fixtureRun.cases[1], 'review_failed', ''), false);

  let finishOld;
  pendingRuns.push(new Promise(resolve => { finishOld = resolve; }));
  const old = context.acLoadRun('run-1');
  await context.acLoadRun('run-1');
  finishOld({ok: true, status: 200, json: () => Promise.resolve({...fixtureRun, title: 'STALE', cases: []})}); await old;
  assert.notEqual(context.acceptanceState.run.title, 'STALE');
  await assert.rejects(context.acReadJSON({files: [{size: 9 * 1024 * 1024}]}), /8 MiB/);
  await assert.rejects(context.acReadJSON({files: [{size: 10, text: () => Promise.resolve('[]')}]}), /顶层须为对象/);
  await assert.rejects(context.acReadJSON({files: [{size: 10, text: () => Promise.resolve('{bad')}]}), /JSON 格式无效/);

  const create = elements['ac-window-create'];
  create.listeners.submit.call(create, {preventDefault() {}}); await flush();
  const created = calls.find(row => row.url === '/api/acceptance/observations');
  const createBody = JSON.parse(created.options.body);
  assert.equal(createBody.start_at, undefined, 'browser must not invent observation start/end');
  assert.equal(createBody.end_at, undefined);
  assert.equal(createBody.as_of, undefined);
  assert.deepEqual(createBody.sources, []);
  elements['ac-quality-file'].files = [{size: 100, text: () => Promise.resolve(JSON.stringify({source_commit: 'd'.repeat(40), report: {cases: []}}))}];
  elements['ac-quality-purpose'].value = 'development';
  const importForm = elements['ac-quality-import'];
  importForm.listeners.submit.call(importForm, {preventDefault() {}}); await flush();
  const imported = calls.find(row => row.url === '/api/acceptance/quality/import');
  assert.equal(JSON.parse(imported.options.body).source_commit, 'd'.repeat(40), 'wrapper commit must survive frontend import');
  console.log('acceptance UI: safe rendering, honest denominators, snapshots, frozen kinds, draft conflict and imports passed');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
