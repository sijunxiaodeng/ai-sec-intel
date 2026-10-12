// Exercise the actual import controls offline: preview/save separation and safe provenance rendering.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class Element {
  constructor(tag) {
    this.tag = tag; this.children = []; this.listeners = {}; this.textContent = "";
    this.value = ""; this.checked = false; this.disabled = false; this.files = [];
  }
  appendChild(child) { this.children.push(child); }
  get firstChild() { return this.children[0]; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  addEventListener(name, listener) { this.listeners[name] = listener; }
  set innerHTML(value) { throw Error("Imported data must never be interpolated into HTML"); }
}
function descendants(element) { return element.children.flatMap(row => [row, ...descendants(row)]); }
function texts(element) { return descendants(element).map(row => row.textContent).join("\n"); }

const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
const source = fs.readFileSync(path.join(__dirname, "../web/app.js"), "utf8");
const elements = {};
for (const match of html.matchAll(/id="([^"]+)"/g)) elements[match[1]] = new Element("div");
assert.ok(elements["asset-observation-provider"]);
assert.match(html, /<input id="asset-observation-is-demo" type="checkbox"\s*\/>/, "demo marker must default to unchecked");
elements["asset-observation-provider"].value = "shodan";
const calls = [], errors = [];
const deferredByUrl = new Map();
function deferNext(url) {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  const queue = deferredByUrl.get(url) || [];
  queue.push(promise); deferredByUrl.set(url, queue);
  return resolve;
}
let failPath = "";
const malicious = "<img src=x onerror=DO_NOT_EXECUTE>";
const item = {
  provider: "shodan", address: "2001:db8::1", port: 11434,
  product: malicious, version: "", observed_at: "2024-01-01T12:34:56Z",
  identity_status: "unknown", time_status: "stale", is_demo: true,
  warnings: [malicious], source_response_sha256: "a".repeat(64), locator: "/matches/0"
};
const observationList = {items: [item], count: 1, demo_count: 1};
const report = {
  cve_id: "CVE-2024-37032", asset_count: 0, demo_count: 0, preview: true,
  counts: {matched_version: 0, unknown: 0, not_matched: 0}, results: [], limitations: [], inventory_source: "provider_export"
};
const demo = {provider: "fofa", content: '{"results":[["192.0.2.1",11434]]}', fields: ["ip", "port"], is_demo: true};
const api = (url, options) => {
  calls.push({url, method: (options || {}).method || "GET", payload: options && options.body ? JSON.parse(options.body) : null});
  if (url === failPath) return Promise.reject(new Error("Provider parse failed"));
  if (deferredByUrl.has(url) && deferredByUrl.get(url).length) return deferredByUrl.get(url).shift();
  const responses = {
    "/api/assets": {items: [], count: 0, demo_count: 0},
    "/api/items": {items: [{cve_id: "CVE-2024-37032"}]},
    "/api/asset-observations": observationList,
    "/api/asset-observations/demo": demo,
    "/api/asset-observations/preview": {...observationList, provider: "fofa", is_demo: true, source_response_sha256: "a".repeat(64), warnings: [malicious], impact: report},
    "/api/asset-observations/import": {created: 1, updated: 0, unchanged: 2},
    "/api/asset-observation-impact/CVE-2024-37032": {...report, preview: false},
    "/api/asset-impact/CVE-2024-37032": {...report, inventory_source: "user_declared", preview: false},
    "/api/assets/preview": {...report, inventory_source: "user_declared"}
  };
  if (!(url in responses)) throw Error("Unexpected UI request: " + url);
  return Promise.resolve(responses[url]);
};
const context = vm.createContext({
  document: {createElement: tag => new Element(tag)}, TextEncoder,
  $: id => elements[id], on: (id, event, handler) => {
    assert.ok(elements[id], "Actual HTML must include handler control " + id);
    elements[id].addEventListener(event, handler);
  }, api, dateText: value => value || "未知", showError: error => errors.push(error.message), clearError: () => {}
});
vm.runInContext(source.slice(source.indexOf("function clear(node)"), source.indexOf("function renderSteps(")), context);
vm.runInContext(source.slice(source.indexOf("var exposureLabels"), source.indexOf("function fillFocus(")), context);
const turn = () => new Promise(resolve => setImmediate(resolve));
const settle = async () => { await turn(); await turn(); };
const click = async id => { elements[id].listeners.click.call(elements[id]); await settle(); };
const change = async id => { elements[id].listeners.change.call(elements[id]); await settle(); };
const lastCall = () => calls[calls.length - 1];

async function main() {
  assert.equal(calls.length, 0, "Installing import controls must not fetch targets or automatically import");
  await context.loadAssets();
  assert.deepEqual(calls.map(row => row.url), ["/api/assets", "/api/items", "/api/asset-observations"], "Entering assets loads separate saved observation list read-only");
  assert.ok(texts(elements["asset-observation-list"]).includes("[2001:db8::1]:11434"));
  assert.ok(texts(elements["asset-observation-list"]).includes(malicious), "Provider text remains literal text");
  assert.ok(texts(elements["asset-observation-list"]).includes("2024-01-01T12:34:56Z"), "Keep observation time, including clock and timezone");
  assert.ok(texts(elements["asset-observation-list"]).includes("历史观测"));
  assert.ok(texts(elements["asset-observation-list"]).includes("虚构演示"));
  assert.ok(texts(elements["asset-observation-list"]).includes("a".repeat(64)));
  assert.ok(texts(elements["asset-observation-list"]).includes("/matches/0"));
  assert.equal(descendants(elements["asset-observation-list"]).filter(row => row.tag === "a").length, 0, "No target link visits or navigation from observation cards");
  failPath = "/api/asset-observations";
  await context.loadAssetObservations();
  assert.equal(elements["asset-observation-count"].textContent, "读取失败");
  assert.ok(texts(elements["asset-observation-list"]).includes("观测读取失败"));
  assert.equal(texts(elements["asset-observation-list"]).includes("2001:db8"), false, "A failed reload must not leave old observations presented as current results");
  failPath = "";
  await context.loadAssetObservations();
  context.renderAssetImpact({...report, preview: false, asset_count: 1, counts: {matched_version: 0, unknown: 1, not_matched: 0}, results: [{
    asset: {asset_id: "OBS-1", name: "Platform record", vendor: "ollama", product: "ollama", version: "", exposure: "unknown", authentication: "unknown", is_demo: true},
    status: "unknown", label: "待确认", reason: "Version unknown", priority: "补充信息", checks: [],
    provider_observation: {...item, identity_status: "exact_cpe"}, evidence_ids: ["OBSERVATION/1", "VULNERABILITY/1"], observation_evidence_ids: ["OBSERVATION/1"]
  }], evidence: [
    {citation_id: "OBSERVATION/1", url: "/api/asset-observations"},
    {citation_id: "VULNERABILITY/1", url: "javascript:DO_NOT_EXECUTE"}
  ]}, elements["asset-observation-impact"]);
  assert.ok(texts(elements["asset-observation-impact"]).includes("已保存平台观测评估"));
  assert.ok(texts(elements["asset-observation-impact"]).includes("明确 CPE 标识"));
  assert.ok(texts(elements["asset-observation-impact"]).includes("a".repeat(64)));
  assert.ok(texts(elements["asset-observation-impact"]).includes("观测证据：OBSERVATION/1"));
  const evidenceLinks = descendants(elements["asset-observation-impact"]).filter(row => row.tag === "a");
  assert.deepEqual(evidenceLinks.map(row => row.href), ["/api/asset-observations"], "Only safe source URLs receive link elements");

  const beforeDemo = calls.length;
  await click("asset-observation-demo");
  assert.equal(calls.length, beforeDemo + 1);
  assert.equal(lastCall().url, "/api/asset-observations/demo");
  assert.equal(elements["asset-observation-is-demo"].checked, true);
  assert.equal(elements["asset-observation-fields"].value, "ip,port");
  assert.equal(elements["asset-observation-provider"].value, "fofa");
  assert.equal(elements["asset-observation-json"].value, demo.content);
  assert.equal(elements["asset-observation-demo"].disabled, false);

  elements["asset-cve"].value = "CVE-2024-37032";
  const declaredMarker = new Element("p"); declaredMarker.textContent = "Declared inventory result retained";
  elements["asset-impact"].appendChild(declaredMarker);
  await click("asset-observation-preview");
  assert.equal(lastCall().url, "/api/asset-observations/preview");
  assert.deepEqual(lastCall().payload.fields, ["ip", "port"]);
  assert.equal(lastCall().payload.cve_id, "CVE-2024-37032");
  assert.equal(lastCall().payload.is_demo, true);
  assert.ok(texts(elements["asset-observation-preview-list"]).includes("尚未保存"));
  assert.ok(texts(elements["asset-observation-impact"]).includes("CVE-2024-37032"));
  assert.ok(texts(elements["asset-impact"]).includes("Declared inventory result retained"), "Observation preview must not overwrite declared inventory assessment");
  assert.equal(calls.filter(row => row.url.endsWith("/import")).length, 0, "Preview does not autosave");
  assert.equal(elements["asset-observation-preview"].disabled, false);

  elements["asset-cve"].value = "";
  elements["asset-observation-fields"].value = "";
  elements["asset-observation-json"].value = '\n {"ip":"192.0.2.1"}\n{"ip":"192.0.2.2"}\n';
  await click("asset-observation-preview");
  assert.equal("cve_id" in lastCall().payload, false, "Preview works before selecting a CVE");
  assert.deepEqual(lastCall().payload.fields, [], "Never infer FOFA column order");
  assert.ok(lastCall().payload.content.includes("\n"), "Original JSONL content stays intact");
  assert.equal(lastCall().payload.content, elements["asset-observation-json"].value, "Do not trim input whitespace: retain record line positions and submitted text digest");

  elements["asset-cve"].value = "CVE-2024-37032";
  const beforeSave = calls.length;
  await click("asset-observation-save");
  assert.deepEqual(calls.slice(beforeSave).map(row => row.url), ["/api/asset-observations/import", "/api/asset-observations"]);
  assert.equal("cve_id" in calls[beforeSave].payload, false, "Saving observation must not silently perform CVE evaluation");
  assert.ok(texts(elements["asset-observation-impact"]).includes("请重新评估"));
  assert.ok(elements["asset-observation-message"].textContent.includes("已存在 2 条"));
  assert.equal(elements["asset-observation-save"].disabled, false);
  await click("asset-observation-evaluate");
  assert.equal(lastCall().url, "/api/asset-observation-impact/CVE-2024-37032");
  assert.equal(elements["asset-observation-evaluate"].disabled, false);

  const beforeFile = calls.length;
  elements["asset-observation-file"].files = [{size: 30, text: () => Promise.resolve('\uFEFF{"matches":[]}')}];
  await change("asset-observation-file");
  assert.equal(elements["asset-observation-json"].value, '{"matches":[]}');
  assert.equal(calls.length, beforeFile, "Reading files is local and does not save or query targets");
  elements["asset-observation-file"].files = [{size: 1024 * 1024 + 1, text: () => { throw Error("Oversized file must not be read"); }}];
  await change("asset-observation-file");
  assert.ok(errors[errors.length - 1].includes("1 MiB"));
  assert.equal(calls.length, beforeFile);

  elements["asset-observation-json"].value = "{invalid JSON";
  await click("asset-observation-preview");
  assert.equal(calls.length, beforeFile);
  assert.ok(errors[errors.length - 1].includes("有效的 JSON"));
  assert.equal(elements["asset-observation-preview"].disabled, false);
  elements["asset-observation-json"].value = JSON.stringify({unicode: "中".repeat(400000)});
  await click("asset-observation-preview");
  assert.equal(calls.length, beforeFile, "Textarea size must be bounded by UTF-8 bytes rather than character count");
  assert.ok(errors[errors.length - 1].includes("1 MiB"));
  elements["asset-observation-json"].value = demo.content;
  elements["asset-observation-fields"].value = "ip,,port";
  await click("asset-observation-preview");
  assert.equal(calls.length, beforeFile);
  assert.ok(errors[errors.length - 1].includes("空项"));
  elements["asset-observation-fields"].value = "ip,port";
  for (const [control, url] of [
    ["asset-observation-demo", "/api/asset-observations/demo"],
    ["asset-observation-preview", "/api/asset-observations/preview"],
    ["asset-observation-save", "/api/asset-observations/import"],
    ["asset-observation-evaluate", "/api/asset-observation-impact/CVE-2024-37032"]
  ]) {
    failPath = url;
    await click(control);
    assert.equal(elements[control].disabled, false, control + " must recover after API rejection");
    assert.equal(errors[errors.length - 1], "Provider parse failed");
  }
  failPath = "";
  await change("asset-cve");
  assert.ok(texts(elements["asset-impact"]).includes("情报已切换"));
  assert.ok(texts(elements["asset-observation-impact"]).includes("情报已切换"));

  // Pending HTTP responses must retain the context at the time the user requested them.
  elements["asset-cve"].value = "CVE-2024-37032";
  const finishSavedObservation = deferNext("/api/asset-observation-impact/CVE-2024-37032");
  await click("asset-observation-evaluate");
  elements["asset-cve"].value = "CVE-2025-0312";
  await change("asset-cve");
  finishSavedObservation({...report, preview: false});
  await settle();
  assert.ok(texts(elements["asset-observation-impact"]).includes("情报已切换"));
  assert.equal(texts(elements["asset-observation-impact"]).includes("CVE-2024-37032"), false, "Delayed saved assessment must not paint a CVE the user has left");
  assert.equal(elements["asset-observation-evaluate"].disabled, false);

  elements["asset-cve"].value = "CVE-2024-37032";
  const finishObservationPreview = deferNext("/api/asset-observations/preview");
  await click("asset-observation-preview");
  elements["asset-cve"].value = "CVE-2025-0312";
  await change("asset-cve");
  const marker = new Element("p"); marker.textContent = "Preview was not replaced after selector changed";
  elements["asset-observation-preview-list"].appendChild(marker);
  finishObservationPreview({...observationList, provider: "fofa", impact: report});
  await settle();
  assert.ok(texts(elements["asset-observation-preview-list"]).includes(marker.textContent), "Delayed preview must not replace the list once its captured CVE is stale");
  assert.ok(texts(elements["asset-observation-impact"]).includes("情报已切换"));

  elements["asset-cve"].value = "CVE-2024-37032";
  const finishEditedPreview = deferNext("/api/asset-observations/preview");
  await click("asset-observation-preview");
  elements["asset-observation-fields"].value = "port,ip";
  // Programmatic changes without events still fail the captured form snapshot check.
  finishEditedPreview({...observationList, provider: "fofa", impact: report});
  await settle();
  assert.ok(texts(elements["asset-observation-preview-list"]).includes(marker.textContent));
  elements["asset-observation-fields"].value = "ip,port";
  const finishRestoredPreview = deferNext("/api/asset-observations/preview");
  await click("asset-observation-preview");
  elements["asset-observation-fields"].value = "port,ip";
  elements["asset-observation-fields"].listeners.input();
  elements["asset-observation-fields"].value = "ip,port";
  elements["asset-observation-fields"].listeners.input();
  finishRestoredPreview({...observationList, provider: "fofa", impact: report});
  await settle();
  assert.ok(texts(elements["asset-observation-preview-list"]).includes("输入已修改"), "Editing and restoring a field still invalidates the older request generation");

  const finishOlderAssessment = deferNext("/api/asset-observation-impact/CVE-2024-37032");
  await click("asset-observation-evaluate");
  await click("asset-observation-preview");
  assert.ok(texts(elements["asset-observation-impact"]).includes("尚未保存"));
  finishOlderAssessment({...report, preview: false});
  await settle();
  assert.ok(texts(elements["asset-observation-impact"]).includes("尚未保存"), "Older saved assessment cannot overwrite a newer preview for the same CVE");

  const finishDeclaredAssessment = deferNext("/api/asset-impact/CVE-2024-37032");
  await click("asset-evaluate");
  elements["asset-cve"].value = "CVE-2025-0312";
  await change("asset-cve");
  finishDeclaredAssessment({...report, preview: false, inventory_source: "user_declared"});
  await settle();
  assert.ok(texts(elements["asset-impact"]).includes("情报已切换"), "Declared inventory shares the same selector context protection");
  elements["asset-cve"].value = "CVE-2024-37032";
  elements["asset-json"].value = '{"assets":[]}';
  const finishDeclaredPreview = deferNext("/api/assets/preview");
  await click("asset-preview");
  elements["asset-json"].value = '{"assets":[{}]}';
  elements["asset-json"].listeners.input();
  finishDeclaredPreview({...report, inventory_source: "user_declared"});
  await settle();
  assert.ok(texts(elements["asset-impact"]).includes("输入已修改"), "Declared preview must not paint the prior inventory after an edit");
  assert.equal(elements["asset-preview"].disabled, false);
  elements["asset-json"].value = '{"assets":[]}';
  const finishOlderDeclaredPreview = deferNext("/api/assets/preview");
  await click("asset-preview");
  await click("asset-evaluate");
  assert.ok(texts(elements["asset-impact"]).includes("已保存清单评估"));
  finishOlderDeclaredPreview({...report, inventory_source: "user_declared"});
  await settle();
  assert.ok(texts(elements["asset-impact"]).includes("已保存清单评估"), "An older declared preview cannot replace a newer saved assessment");
  assert.ok(calls.every(row => row.url.startsWith("/api/")), "All network requests stay in the local API");
  console.log("asset observations UI: import/preview/save, safe provenance, error recovery and deferred context races passed");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
