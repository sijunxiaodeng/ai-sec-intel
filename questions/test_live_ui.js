const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const elements = {'update-notice': {hidden: true}, overview: {hidden: false}, monitor: {hidden: true}};
let tick, completed = 'first', running = false, loads = 0, polls = 0, reloads = 0;
let overviewResult = () => Promise.resolve(true);
let feedLoads = 0, feedResult = () => Promise.resolve({items: []});
const handlers = {};
const ctx = vm.createContext({
  Promise,
  document: {hidden: false, querySelector: () => ({content: 'old'}), addEventListener() {}},
  window: {location: {reload() {reloads++;}}, addEventListener() {}},
  monitorRefreshing: false,
  $: id => elements[id],
  api: () => Promise.resolve({web_version: 'new'}),
  loadMonitorStatus: light => {assert.equal(light, true); polls++; return Promise.resolve({last_run: completed, running});},
  loadOverview: () => {loads++; return overviewResult();},
  loadItems: view => {assert.equal(view, 'monitor'); feedLoads++; return feedResult();},
  on: (id, event, action) => {handlers[id] = action;},
  setInterval: action => {tick = action;},
});
async function main() {
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/live.js'), 'utf8'), ctx);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(elements['update-notice'].hidden, false);
  assert.equal(reloads, 0, 'updates must not discard unfinished input');
  assert.equal(loads, 0);
  completed = 'second';
  await tick();
  assert.equal(loads, 1, 'completed background round refreshes visible overview');
  await tick();
  assert.equal(loads, 1, 'unchanged state avoids heavy overview requests');

  completed = 'third';
  overviewResult = () => Promise.resolve(false);
  await tick();
  assert.equal(loads, 2);
  overviewResult = () => Promise.resolve(true);
  await tick();
  assert.equal(loads, 3, 'a handled overview failure must retry the same completion');
  await tick();
  assert.equal(loads, 3, 'a successful retry consumes the completion exactly once');

  elements.overview.hidden = true;
  elements.monitor.hidden = false;
  completed = 'fourth';
  feedResult = () => Promise.reject(new Error('transient feed failure'));
  await tick();
  feedResult = () => Promise.resolve({items: []});
  await tick();
  assert.equal(feedLoads, 2, 'a rejected feed request must retry the same completion');
  await tick();
  assert.equal(feedLoads, 2);

  completed = 'fifth';
  running = true;
  await tick();
  assert.equal(feedLoads, 2, 'do not refresh the feed while the monitor owns it');
  running = false;
  await tick();
  assert.equal(feedLoads, 3, 'a completion observed while running must remain pending');

  // A failed version request must not release the busy guard while the actual
  // data request is still in flight, or focus events can duplicate heavy loads.
  completed = 'sixth';
  ctx.api = () => Promise.reject(new Error('version endpoint unavailable'));
  let finishFeed;
  feedResult = () => new Promise(resolve => {finishFeed = resolve;});
  const pending = tick();
  await new Promise(resolve => setImmediate(resolve));
  const duringRequest = polls;
  await tick();
  assert.equal(polls, duringRequest, 'version failure must not overlap data refreshes');
  finishFeed({items: []});
  await pending;
  await tick();
  assert.equal(feedLoads, 4, 'a version failure does not invalidate a successful data refresh');

  const before = polls;
  ctx.document.hidden = true;
  await tick();
  assert.equal(polls, before);
  ctx.document.hidden = false;
  ctx.monitorRefreshing = true;
  await tick();
  assert.equal(polls, before, 'manual refresh owns its progress polling');
  handlers['reload-page']();
  assert.equal(reloads, 1);
  console.log('live UI checks passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});
