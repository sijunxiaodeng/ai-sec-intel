// Exercise production text formatting and truthful overview counts, offline.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ''; this.listeners = {}; }
  appendChild(child) { this.children.push(child); return child; }
  get firstChild() { return this.children[0]; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  setAttribute(key, value) { this[key] = value; }
  addEventListener(event, listener) { this.listeners[event] = listener; }
  set innerHTML(value) { throw Error('Source HTML must never execute'); }
}
const descendants = el => el.children.flatMap(child => [child, ...descendants(child)]);
const text = el => [el.textContent, ...el.children.map(text)].join('');
const document = {createElement: tag => new Element(tag), createTextNode: value => {const el = new Element('#text'); el.textContent = value; return el;}};
const context = vm.createContext({document});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/answer-content.js'), 'utf8'), context);
const parent = new Element('div');
context.renderAnswerContent(parent, '# Source-backed result\n\n<img src=x onerror=DO_NOT_EXECUTE> **Risk** `0.1.33` [CVE/F1] [missing]\n\n- first\n- second\n\n| Field | Value |\n| --- | --- |\n| CVE | <script>INERT</script> |\n\n```sh\necho <unsafe>\n```', {'CVE/F1':'qa-evidence-0'});
const nodes = descendants(parent);
assert.equal(nodes.filter(el => el.tag === 'a').length, 1);
assert.equal(nodes.find(el => el.tag === 'a').href, '#qa-evidence-0');
assert.equal(nodes.filter(el => el.tag === 'li').length, 2);
assert.equal(nodes.filter(el => el.tag === 'table').length, 1);
assert.equal(nodes.filter(el => el.tag === 'pre').length, 1);
assert.equal(nodes.filter(el => el.tag === 'script' || el.tag === 'img').length, 0);
assert.ok(text(parent).includes('<script>INERT</script>'));
assert.ok(text(parent).includes('[missing]'));
assert.ok(text(parent).includes('echo <unsafe>'));
const history = new Element('div');
context.renderAnswerContent(history, 'Historical [CVE/F1]');
assert.equal(descendants(history).filter(el => el.tag === 'a').length, 0, 'old citations must not point to a different current turn');

const app = fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8');
const elements = Object.fromEntries(['stats','monitor-line','recent','steps','overview-sources','overview-source-count'].map(id => [id, new Element('div')]));
let response;
const overview = vm.createContext({document, Number, $: id => elements[id], api: () => Promise.resolve(response),
  setOfflineMode() {}, setPill() {}, formatStamp: value => value, monitorResultLabel: value => value,
  sourceLabel: value => value, pageSlice: items => ({items}), renderPager() {}, renderSteps() {}, renderItemRow() {}, showError: error => {throw error;}, OVERVIEW_PAGE_SIZE: 8});
vm.runInContext(app.slice(app.indexOf('function clear(node)'), app.indexOf('function renderSteps(')), overview);
vm.runInContext(app.slice(app.indexOf('function loadOverview()'), app.indexOf('var monitorScope')), overview);
async function main() {
  response = {items:120, source_count:13, library:{documents:7}, recent:[], steps:[], monitor:{last_count:0, collection_summary:{raw_inserted:12, counts_complete:false, sources:[{source:'NVD',status:'partial'},{source:'OSV',status:'error'}]}}};
  await overview.loadOverview();
  const values = () => elements.stats.children.map(el => el.children.find(child => child.tag === 'b').textContent);
  assert.deepEqual(values(), ['120','暂无数据','12','7'], 'a missing completed round is not a measured zero');
  assert.ok(text(elements.stats).includes('统计可能不完整'));
  assert.ok(descendants(elements['overview-sources']).some(el => el.className === 'source-health-status st-bad'));
  response.monitor = {last_run:'2026-10-16T07:00:00Z', last_count:0, last_status:'ok'};
  await overview.loadOverview();
  assert.deepEqual(values(), ['120','0','暂无数据','7'], 'a measured zero stays zero, absent source counts stay unknown');
  vm.runInContext(app.slice(app.indexOf('var LIST_PAGE_SIZE'), app.indexOf('function showError(')), overview);
  const records = Array.from({length:41}, (_, i) => ({id:i}));
  let reloads = 0;
  const pageOne = overview.pageSlice(records, 'monitor', 20), pager = new Element('div');
  overview.renderPager(pager, 'monitor', pageOne, () => reloads++);
  const buttons = descendants(pager).filter(el => el.tag === 'button');
  assert.equal(buttons[0].disabled, true);
  buttons[1].listeners.click();
  assert.equal(overview.pageSlice(records, 'monitor', 20).items[0].id, 20);
  assert.equal(reloads, 1);
  assert.equal(overview.pageSlice(records.slice(0,5), 'monitor', 20).page, 1, 'filtering must clamp a now-missing page');
  console.log('workbench UI: safe answer formatting/citations, history scope, honest metrics and actual next-page/filter-clamp handlers passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});
