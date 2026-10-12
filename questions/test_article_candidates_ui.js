// Execute the actual detail renderer/button handler in an offline minimal DOM.
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
const panel = new Element("div"), calls = [];
let result = {detail: "Local fixture", notice: "Candidates require review", items: [{
  category: "paper", title: "<script>DO_NOT_EXECUTE</script>", explicit_cve_mention: false,
  content_scope: "abstract", retrieved_at: "2026-10-12T00:00:00Z", association_notice: "Reference only",
  match_basis: [{label: "Mechanism", term: "path_traversal", citation_id: "DOC-1/LIB-1"}],
  evidence: [{text: "<img onerror=DO_NOT_EXECUTE>", citation_id: "DOC-1/LIB-1", url: "https://arxiv.org/abs/2401.12345", locator: "abstract", source_response_sha256: "a".repeat(64)}]
}]};
const context = vm.createContext({
  document: {createElement: tag => new Element(tag)}, $: () => panel,
  api: url => { calls.push(url); return result instanceof Error ? Promise.reject(result) : Promise.resolve(result); },
  itemSourceLabels: () => [], missingText: (value, fallback) => value || fallback,
  scoreText: value => String(value), epssText: () => "unknown", kevText: () => "unknown",
  dateText: value => value, isDemoItem: () => false, renderAssessment: () => {}, renderGuidance: () => {},
  showError: () => {}, clearError: () => {}
});
const source = fs.readFileSync(path.join(__dirname, "../web/app.js"), "utf8");
vm.runInContext(source.slice(source.indexOf("function clear(node)"), source.indexOf("function renderSteps(")), context);
vm.runInContext(source.slice(source.indexOf("function renderArticleCandidates("), source.indexOf("var exposureLabels")), context);
const turn = () => new Promise(resolve => setImmediate(resolve));
async function main() {
  context.renderDetail({cve_id: "CVE-2024-37032", cvss: 8.8, references: [], papers: []});
  const section = panel.querySelector(".article-candidates");
  assert.ok(section, "actual detail render must expose the candidates section");
  const button = section.children.find(row => row.tag === "button");
  assert.equal(calls.length, 0, "detail opening does not trigger a hidden search");
  button.listeners.click();
  await turn();
  assert.deepEqual(calls, ["/api/article-candidates/CVE-2024-37032"]);
  assert.equal(button.disabled, false);
  const content = descendants(section);
  assert.ok(content.some(row => row.textContent === "<img onerror=DO_NOT_EXECUTE>"));
  assert.ok(content.some(row => row.href === "https://arxiv.org/abs/2401.12345" && row.rel === "noopener"));
  assert.ok(content.some(row => row.textContent.includes("a".repeat(64))));
  result = new Error("Local search unavailable");
  button.listeners.click();
  await turn();
  assert.ok(descendants(section).some(row => row.textContent === "Local search unavailable"));
  assert.equal(button.disabled, false);
  result = {detail: "No candidates does not mean no related publications", items: [], notice: "Coverage limited"};
  button.listeners.click();
  await turn();
  assert.ok(descendants(section).some(row => row.textContent === result.detail));
  console.log("article candidates UI: detail -> GET -> evidence/error/empty rendering passed");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
