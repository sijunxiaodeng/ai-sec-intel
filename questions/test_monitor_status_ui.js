// Execute production monitor renderers without browser/network dependencies.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
process.env.TZ = 'UTC'; // Display must use Beijing even on a UTC host/browser.
class Element {
  constructor() { this.children = []; this.textContent = ''; this.hidden = false; this.classList = {toggle() {}}; }
  appendChild(child) { this.children.push(child); }
  get firstChild() { return this.children[0]; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  set innerHTML(value) { throw Error('Source strings must remain text'); }
}
const elements = {};
const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
for (const match of html.matchAll(/id="([^"]+)"/g)) elements[match[1]] = new Element();
const source = fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8');
let response, statusText = '';
const context = vm.createContext({
  Date, Intl, Number, String, Array,
  $: id => elements[id],
  clear: el => { el.children = []; },
  add: (parent, tag, cls, text) => { const el = new Element(); el.textContent = text; parent.appendChild(el); return el; },
  sourceLabel: value => value || '未知来源',
  setOfflineMode: value => { context.offlineDemo = value; },
  setTeamHealth() {}, renderCollectPipeline() {},
  setMonitorStatus: value => { statusText = value; },
  api: () => Promise.resolve(response),
  offlineDemo: false, monitorRefreshing: false, lastMonitorStatus: null,
});
function loadBetween(start, end) {
  const first = source.indexOf(start), last = source.indexOf(end, first + start.length);
  assert.ok(first >= 0 && last > first, start);
  vm.runInContext(source.slice(first, last), context);
}
loadBetween('function dateText(value)', 'function epssText(');
loadBetween('function formatStamp(value)', 'function stageStatusLabel(');
loadBetween('function renderMonitorLive(data, opts)', 'function loadMonitorStatus(');
loadBetween('function loadMonitorStatus(', 'function loadOverview(');
const collection = {
  status: 'partial', finished_at: '2026-10-13T20:30:00Z', counts_complete: false,
  raw_inserted: 38, raw_updated: 4, raw_fetched: 83,
  source_total: 13, source_success: 5, source_partial: 2, source_failed: 6, source_skipped: 0,
  sources: [
    {source: 'NVD', status: 'partial', inserted: 38, updated: 4, recent_success: true, pending: true},
    {source: 'UNAVAILABLE', status: 'failed', inserted: null, error: '<img src=x onerror=DO_NOT_EXECUTE>'},
  ],
};
async function main() {
  assert.equal(context.dateText('2026-10-13'), '2026-10-13', 'date-only input must not invent a time');
  assert.equal(context.formatStamp('2026-10-13T20:30:00Z'), '2026-10-14 04:30:00（北京时间）');
  assert.equal(context.formatStamp('2026-10-14T04:30:00+08:00'), '2026-10-14 04:30:00（北京时间）');
  assert.equal(context.dateText('2026-10-13T20:30:00.123456Z'), '2026-10-14 04:30:00（北京时间）');
  assert.equal(context.formatStamp('2026-10-14T04:30:00'), '2026-10-14 04:30:00（时区未标明）');

  response = {last_run: '2026-10-14T05:00:00Z', last_count: 0, last_status: 'partial',
    collection_summary: collection, next_run: '2026-10-14T05:15:00Z', interval_minutes: 15};
  await context.loadMonitorStatus();
  assert.match(elements['monitor-live-last'].textContent, /上次AI情报新增 0 条/);
  assert.match(elements['monitor-live-state'].textContent, /上次刷新部分成功/);
  assert.match(elements['monitor-live-sources'].textContent, /已确认来源记录新增 38/);
  assert.match(elements['monitor-live-sources'].textContent, /来源成功 5\/13 · 部分成功 2 · 失败 6/);
  assert.match(elements['monitor-live-sources'].textContent, /计数不完整/);
  assert.match(elements['monitor-live-sources'].textContent, /2026-10-14 04:30:00/,
    'retained source statistics have their own completion time, not the latest refresh time');
  assert.match(elements['monitor-line'].textContent, /AI情报新增 0/);
  assert.match(elements['monitor-line'].textContent, /失败 6/);
  assert.match(statusText, /已确认来源记录新增 38/);
  assert.equal(elements['monitor-source-details'].hidden, false);
  assert.match(elements['monitor-source-list'].children[0].textContent, /最近发布采集成功 · 历史窗口仍待追赶/);
  assert.match(elements['monitor-source-list'].children[1].textContent, /来源记录新增 未提供/);
  assert.ok(elements['monitor-source-list'].children[1].textContent.includes('<img src=x onerror=DO_NOT_EXECUTE>'));

  context.monitorRefreshing = true;
  context.renderMonitorLive({...response, running: true}, {elapsedSec: 12});
  assert.match(elements['monitor-live-state'].textContent, /正在刷新/);
  assert.match(elements['monitor-live-sources'].textContent, /最近来源采集/);
  assert.match(elements['monitor-live-sources'].textContent, /04:30:00/);
  context.monitorRefreshing = false;

  const incomplete = context.collectionSummaryText({status: 'timeout', counts_complete: false,
    raw_inserted: null, raw_updated: null, source_total: 13});
  assert.match(incomplete, /新增 未提供/);
  assert.match(incomplete, /来源成功 未提供\/13/);
  assert.doesNotMatch(incomplete, /新增 0|失败 0|更新 0/);
  assert.match(context.collectionSummaryText(null), /统计未提供/);
  assert.equal(context.monitorCount('<script>38</script>'), '未提供');

  const complete = {...collection, status: 'success', counts_complete: true,
    source_success: 13, source_partial: 0, source_failed: 0, raw_inserted: 0};
  const completeText = context.collectionSummaryText(complete);
  assert.match(completeText, /来源记录新增 0/);
  assert.doesNotMatch(completeText, /已确认来源记录新增|计数不完整/);
  response = {last_run: '2026-10-14T05:00:00Z', last_status: 'failed', last_count: 0};
  await context.loadMonitorStatus();
  assert.match(elements['monitor-live-state'].textContent, /上次刷新失败/);
  assert.match(elements['monitor-live-sources'].textContent, /统计未提供/);
  assert.equal(elements['monitor-source-details'].hidden, true);
  assert.ok(html.includes('同一CVE在不同来源可能重复计数'));
  console.log('monitor status UI regression checks passed');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
