// A CVE selection must not re-enter the view, reload bulk data or reset work.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const app = fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8');
const source = app.slice(app.indexOf('var detailRequestVersion = 0;'), app.indexOf('function renderAssessment('));
const first = 'CVE-2026-109985', second = 'CVE-2026-96620';
function row(id) {
  const attributes = {'data-item-id': id};
  const classes = new Set(['row']);
  return {attributes, classes, getAttribute: name => attributes[name],
    setAttribute: (name, value) => {attributes[name] = value;},
    classList: {toggle: (name, on) => {if (on) classes.add(name); else classes.delete(name);}}};
}
function setup(hidden = false) {
  const rows = [row(first), row(second)];
  const elements = {
    enrich: {hidden}, 'enrich-list': {scrollTop: 320, querySelectorAll: () => rows},
    'asset-json': {value: '{"assets":[{"name":"unsaved draft"}]}'},
    'asset-cve': {value: first}, 'asset-drawer': {open: true}
  };
  const requests = [], navigation = [], rendered = [], errors = [], toasts = [];
  const context = vm.createContext({
    selectedEnrichId: null, $: id => elements[id], clearError() {},
    setView: name => {navigation.push(name); elements.enrich.hidden = false;},
    api: url => new Promise((resolve, reject) => requests.push({url, resolve, reject})),
    renderDetail: detail => rendered.push(detail.cve_id),
    showToast: (...args) => toasts.push(args), showError: error => errors.push(error.message)
  });
  vm.runInContext(source, context);
  return {context, rows, elements, requests, navigation, rendered, errors, toasts};
}
async function main() {
  const s = setup();
  const before = JSON.stringify(s.elements);
  let result = s.context.openDetail(first);
  assert.deepEqual(s.navigation, [], 'selecting in the current view must not invoke bulk/asset loaders');
  assert.deepEqual(s.requests.map(r => r.url), ['/api/items/' + first]);
  assert.equal(s.rows[0].attributes['aria-pressed'], 'true');
  assert.equal(s.rows[0].classes.has('is-selected'), true, 'selection feedback is immediate');
  assert.equal(s.rows[1].attributes['aria-pressed'], 'false');
  s.requests[0].resolve({cve_id: first});
  await result;
  assert.deepEqual(s.rendered, [first]);
  assert.equal(JSON.stringify(s.elements), before, 'drafts, drawer, dropdown and reading position stay unchanged');

  result = s.context.openDetail(second);
  assert.equal(s.rows[0].classes.has('is-selected'), false);
  assert.equal(s.rows[1].attributes['aria-pressed'], 'true');
  s.requests[1].resolve({cve_id: second});
  await result;
  assert.deepEqual(s.requests.map(r => r.url), ['/api/items/' + first, '/api/items/' + second]);
  assert.deepEqual(s.navigation, []);

  const entering = setup(true);
  result = entering.context.openDetail(first);
  assert.deepEqual(entering.navigation, ['enrich'], 'links from other modules must still navigate');
  entering.requests[0].resolve({cve_id: first});
  await result;
  assert.deepEqual(entering.rendered, [first]);

  const racing = setup();
  const old = racing.context.openDetail(first), current = racing.context.openDetail(second);
  racing.requests[1].resolve({cve_id: second});
  await current;
  racing.requests[0].resolve({cve_id: first});
  await old;
  assert.deepEqual(racing.rendered, [second], 'a slow previous response must not replace the selected CVE');
  assert.equal(racing.rows[1].attributes['aria-pressed'], 'true');
  assert.equal(racing.rows[0].attributes['aria-pressed'], 'false');

  const failed = setup();
  const obsolete = failed.context.openDetail(first), newest = failed.context.openDetail(second);
  failed.requests[0].reject(new Error('obsolete error'));
  await obsolete;
  assert.deepEqual(failed.errors, []);
  failed.requests[1].reject(new Error('source unavailable'));
  await newest;
  assert.deepEqual(failed.errors, ['source unavailable']);
  assert.equal(failed.toasts.at(-1)[1], 'error');

  const mismatch = setup();
  result = mismatch.context.openDetail(first);
  mismatch.requests[0].resolve({cve_id: second});
  await result;
  assert.deepEqual(mismatch.rendered, []);
  assert.equal(mismatch.errors.length, 1, 'wrong-CVE responses must remain rejected');
  console.log('enrich detail UI: one detail request per selection, preserved context, navigation, selection semantics, stale responses and errors passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});
