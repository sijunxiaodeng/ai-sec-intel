// Exercise the real PoC renderer and request handlers without external HTTP or code execution.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this.textContent = ""; }
  appendChild(child) { this.children.push(child); }
  get firstChild() { return this.children[0]; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  addEventListener(name, listener) { this.listeners[name] = listener; }
  querySelector(selector) { return descendants(this).find(row => (row.className || "").split(" ").includes(selector.slice(1))); }
  set innerHTML(value) { throw Error("HTML injection is forbidden"); }
}
function descendants(element) { return element.children.flatMap(row => [row, ...descendants(row)]); }
const panel = new Element("div"), calls = [], errors = [], toasts = [];
const enrichList = {querySelectorAll: () => []}; // List selection is covered by test_enrich_detail_ui.js.
const cve = "CVE-2024-37032";
function fixture(id = cve) {
  return {cve_id: id, status: "static_reviewed", detail: "Only static review", items: [{
    candidate_id: "candidate-1", repository: "https://github.com/example/poc", commit_sha: "1".repeat(40),
    status: "static_reviewed", validation: "not_run", dependencies: [{declaration: "requests==2.0.0", line: 1, evidence_ids: ["POC-1"]}],
    files: [{path: "poc.py", size: 123, sha256: "2".repeat(64), git_blob_sha: "3".repeat(40),
      url: "https://github.com/example/poc/blob/" + "1".repeat(40) + "/poc.py", syntax_status: "parsed_not_executed"}],
    review: {summary: "<script>NOT_EXECUTED</script>", capability: "Writes target files; no runtime verification",
      reviewed_by: "Project review", review_method: "Pinned source static review", dependencies_file: "requirements.txt",
      findings: [{text: "Source requests a model pull", file: "poc.py", lines: [20, 24], evidence_ids: ["POC-1"]}],
      target_version_claim: {version: "0.1.33", file: "README.md", lines: [2, 3]}, notes: ["Do not run outside an isolated lab"]},
    evidence_ids: ["POC-1", "POC-2", "POC-3"]}],
    evidence: [{citation_id: "POC-1", text_kind: "poc_source_declaration", text: "<img onerror=NOT_EXECUTED>", locator: "poc.py lines 20–24", source_response_sha256: "2".repeat(64),
      url: "/api/poc-code/CVE-2024-37032/evidence/POC-1"},
      {citation_id: "POC-2", text_kind: "development_static_review", text: "unsafe URL must remain text", locator: "README.md lines 2–3", source_response_sha256: "4".repeat(64), url: "javascript:NOT_EXECUTED"},
      {citation_id: "POC-3", text_kind: "poc_source_metadata", text: "Pinned candidate metadata", locator: "catalog", source_response_sha256: "4".repeat(64)}],
    latest_attempt: {status: "static_reviewed", queried_at: "2026-10-12T00:00:00Z"}};
}
let result = fixture();
const context = vm.createContext({
  // The full browser script initializes this state before the extracted renderer.
  offlineDemo: false,
  document: {createElement: tag => new Element(tag)}, $: id => id === "enrich-list" ? enrichList : panel,
  api: (url, options) => { calls.push({url, options}); return typeof result === "function" ? result(url, options) : result instanceof Error ? Promise.reject(result) : Promise.resolve(result); },
  itemSourceLabels: () => [], missingText: (value, fallback) => value || fallback,
  scoreText: value => String(value), epssText: () => "unknown", kevText: () => "unknown",
  dateText: value => value, isDemoItem: () => false, renderAssessment: () => {}, renderGuidance: () => {},
  showError: error => errors.push(error.message), clearError: () => {}, setView: () => {}, showToast: message => toasts.push(message)
});
const source = fs.readFileSync(path.join(__dirname, "../web/app.js"), "utf8");
vm.runInContext(source.slice(source.indexOf("function clear(node)"), source.indexOf("function renderSteps(")), context);
vm.runInContext(source.slice(source.indexOf("var detailRequestVersion = 0;"), source.indexOf("function renderAssessment(")), context);
vm.runInContext(source.slice(source.indexOf("function renderArticleCandidates("), source.indexOf("var exposureLabels")), context);
const turn = () => new Promise(resolve => setImmediate(resolve));
function open(id = cve, report) {
  context.renderDetail({cve_id: id, cvss: 8.8, references: [], papers: [], poc_code: report});
  const section = panel.querySelector(".poc-code");
  assert.ok(section, "actual detail render must expose PoC source review");
  return {section, buttons: section.children.filter(row => row.tag === "button")};
}
function rendered(section) { return descendants(section).map(row => row.textContent).join("\n"); }
async function main() {
  let state = open();
  assert.equal(calls.length, 0, "opening details must not collect code or initiate hidden network requests");
  assert.equal(state.buttons[1].textContent, "收集并静态审查代码");
  state.buttons[0].listeners.click();
  await turn();
  assert.equal(calls[0].url, "/api/poc-code/" + cve);
  assert.equal(calls[0].options, undefined, "view action is GET only");
  let nodes = descendants(state.section);
  assert.ok(nodes.some(row => row.textContent === "<img onerror=NOT_EXECUTED>"));
  assert.ok(nodes.some(row => row.textContent.includes("<script>NOT_EXECUTED</script>")));
  assert.ok(nodes.some(row => row.href && row.href.startsWith("/api/poc-code/") && row.rel === "noopener"));
  assert.ok(nodes.every(row => !row.href || !/^javascript:/i.test(row.href)));
  assert.ok(rendered(state.section).includes("1".repeat(40)));
  assert.ok(rendered(state.section).includes("2".repeat(64)));
  assert.ok(rendered(state.section).includes("3".repeat(40)));
  assert.ok(rendered(state.section).includes("行号：[20,24]"));
  assert.ok(rendered(state.section).includes("not_run"));
  assert.ok(rendered(state.section).includes("静态审查不证明可运行、利用成功或 RCE 已复现"));
  assert.ok(rendered(state.section).includes("仅来源声明，未安装或验证"));
  assert.ok(rendered(state.section).includes("requests==2.0.0"));
  assert.ok(!rendered(state.section).includes('"declaration"'), "dependency declarations appear as readable text rather than internal JSON");
  assert.ok(rendered(state.section).includes("依赖声明位置：requirements.txt · 行号：1"));
  assert.ok(rendered(state.section).includes("来源声明摘录：POC-1"));
  assert.ok(rendered(state.section).includes("开发阶段静态审查记录：POC-2"));
  assert.ok(rendered(state.section).includes("来源元数据：POC-3"));
  assert.ok(rendered(state.section).includes("证据绑定摘要：" + "4".repeat(64)));
  assert.ok(!rendered(state.section).includes("文件 SHA-256：" + "4".repeat(64)), "catalog fingerprints cannot be presented as raw source file hashes");
  assert.ok(rendered(state.section).includes("2026-10-12T00:00:00Z"));
  state.buttons[1].listeners.click();
  await turn();
  assert.equal(calls[1].url, "/api/poc-code/" + cve + "/collect");
  assert.equal(calls[1].options.method, "POST");
  assert.equal(calls[1].options.body, undefined, "client cannot supply a download URL or command");
  assert.ok(state.buttons.every(button => button.disabled === false));

  result = new Error("Source unavailable; previous record retained");
  state.buttons[1].listeners.click();
  await turn();
  assert.ok(rendered(state.section).includes(result.message));
  assert.ok(state.buttons.every(button => button.disabled === false));

  const untouchedCalls = calls.length;
  state = open(cve, {...fixture(), stale: true, latest_attempt: {status: "error", queried_at: "2026-10-12T01:00:00Z", error_type: "integrity_error", detail: "Pinned file mismatch"}});
  assert.equal(calls.length, untouchedCalls, "a supplied local report renders without fetching");
  assert.ok(rendered(state.section).includes("历史记录"));
  assert.ok(rendered(state.section).includes("Pinned file mismatch"));
  assert.ok(rendered(state.section).includes("失败类型：integrity_error"));
  assert.ok(rendered(state.section).includes("2026-10-12T01:00:00Z"));

  result = {cve_id: cve, status: "unconfigured", detail: "No pinned candidate configured", items: []};
  state.buttons[0].listeners.click();
  await turn();
  assert.ok(rendered(state.section).includes("尚未登记候选来源"));
  assert.ok(rendered(state.section).includes("这不表示没有公开 PoC"));

  result = fixture("CVE-2025-0312");
  state.buttons[0].listeners.click();
  await turn();
  assert.ok(rendered(state.section).includes("未采用该响应"));
  assert.ok(!rendered(state.section).includes("1".repeat(40)), "mismatched CVE cannot inject a code record");

  let finish;
  result = () => new Promise(resolve => { finish = resolve; });
  state.buttons[1].listeners.click();
  const oldSection = state.section;
  state = open("CVE-2025-0312");
  const newText = rendered(state.section);
  finish(fixture());
  await turn();
  assert.equal(rendered(state.section), newText, "delayed old-CVE collection cannot repaint a new detail");
  assert.ok(!rendered(oldSection).includes("1".repeat(40)), "detached panel is not updated by a delayed response");

  // Root-relative links reject browser backslash normalization into a network-path URL.
  const invalidUrls = ["//evil.example/poc", "/\\evil.example/poc", "http://evil.example/poc", "https://evil.example/\npoison"];
  for (const url of invalidUrls) {
    const report = fixture("CVE-2025-0312");
    report.items[0].repository = url;
    report.items[0].files[0].url = url;
    report.evidence.forEach(row => { row.url = url; });
    state = open("CVE-2025-0312", report);
    assert.ok(descendants(state.section).every(row => !row.href), "unsafe evidence/repository URL stays text: " + JSON.stringify(url));
  }
  state = open(cve, {cve_id: cve, status: "ok"});
  assert.ok(rendered(state.section).includes("未采用该响应"), "missing item collection cannot become a blank successful result");

  // The earlier /api/items request itself must not restore an old CVE and its PoC panel.
  let finishOldDetail, finishNewDetail;
  result = url => new Promise(resolve => {
    if (url.endsWith(cve)) finishOldDetail = resolve;
    else finishNewDetail = resolve;
  });
  context.openDetail(cve);
  context.openDetail("CVE-2025-0312");
  finishNewDetail({cve_id: "CVE-2025-0312", papers: [], references: [], poc_code: fixture("CVE-2025-0312")});
  await turn();
  const currentText = rendered(panel);
  finishOldDetail({cve_id: cve, papers: [], references: [], poc_code: fixture()});
  await turn();
  assert.equal(rendered(panel), currentText, "slower earlier detail GET cannot restore the old PoC panel");
  assert.ok(toasts[toasts.length - 1].includes("CVE-2025-0312"), "stale detail success does not produce an old-CVE success toast");

  let rejectOldDetail;
  result = url => url.endsWith(cve) ? new Promise((_, reject) => { rejectOldDetail = reject; }) : Promise.resolve({cve_id: "CVE-2025-0312", papers: [], references: []});
  const errorsBefore = errors.length;
  context.openDetail(cve);
  context.openDetail("CVE-2025-0312");
  await turn();
  rejectOldDetail(new Error("Stale old detail failure"));
  await turn();
  assert.equal(errors.length, errorsBefore, "stale detail errors cannot pollute the current CVE");

  result = {cve_id: "CVE-2025-0312", papers: [], references: []};
  context.openDetail(cve);
  await turn();
  assert.ok(errors[errors.length - 1].includes("CVE 与请求不一致"), "current detail response must bind to the requested CVE");

  context.offlineDemo = true;
  const beforeOffline = calls.length;
  state = open(cve, fixture());
  assert.equal(calls.length, beforeOffline, "offline opening renders supplied local code review without collecting code");
  assert.ok(rendered(state.section).includes("1".repeat(40)), "offline details retain the supplied pinned source metadata");
  const fetchButton = panel.children.find(row => row.tag === "button" && row.textContent === "离线演示使用已加载的样例证据");
  assert.ok(fetchButton);
  assert.equal(fetchButton.disabled, true);
  fetchButton.listeners.click();
  await turn();
  assert.equal(calls.length, beforeOffline, "offline detail cannot fetch external documents");
  result = fixture();
  state.buttons[0].listeners.click();
  await turn();
  assert.equal(calls[calls.length - 1].url, "/api/poc-code/" + cve, "reading saved static review remains available offline");
  assert.equal(calls[calls.length - 1].options, undefined);
  assert.ok(rendered(state.section).includes("1".repeat(40)));
  console.log("PoC source UI: actual detail GET/POST, metadata/evidence, failure, stale, mismatch, detached-response and offline record checks passed");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
