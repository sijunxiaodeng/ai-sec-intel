/* Asset decisions and bounded research traces; all source text is rendered as text. */
var riskOffset = 0;
var riskPageSize = 30;
var riskRequest = 0;
var riskEditing = false;
var lastInvestigationRender = "";
var taskLabels = {pending: "排队中", running: "研判中", retry: "等待重试", done: "已完成", failed: "失败待处理", skipped: "输入已变化，旧任务跳过"};
var dispositionLabels = {pending: "待处理", in_progress: "处理中", pending_review: "待复核", resolved: "已解决", accepted_risk: "接受风险"};
var gapLabels = {evidence_archive: "来源正文", cvss: "评分", affected_versions: "受影响版本", deployment_conditions: "部署条件", source_conflict: "来源冲突", exploit_probability: "EPSS", known_exploitation: "已知利用状态", research_evidence: "关联研究"};
var stopLabels = {evidence_sufficient: "所检查证据已齐备", available_tools_exhausted: "已尝试所有适用工具", tool_budget_exhausted: "达到工具调用上限", time_budget_exhausted: "达到本轮时间预算"};

function riskPath(row) {
  return "/api/risks/" + encodeURIComponent(row.asset_id) + "/" + encodeURIComponent(row.cve_id);
}

function renderRiskEvidence(target, row) {
  var detail = add(target, "details", "");
  add(detail, "summary", "", "查看判断依据与来源");
  (row.checks || []).forEach(function (check) {
    add(detail, "p", "desc", check.range + "；" + check.reason);
  });
  (row.evidence || []).forEach(function (evidence) {
    add(detail, "p", "meta", (evidence.citation_id || "") + " · " + formatStamp(evidence.retrieved_at));
    add(detail, "p", "desc", evidence.text || evidence.locator || "");
    var url = evidence.url || "";
    if (/^https:\/\//i.test(url)) {
      var link = add(detail, "a", "", "打开证据来源");
      link.href = url; link.target = "_blank"; link.rel = "noopener noreferrer";
    }
  });
  (row.warnings || []).forEach(function (warning) { add(detail, "p", "hint", warning); });
  (row.uncertainties || []).forEach(function (uncertainty) { add(detail, "p", "hint", "待确认：" + uncertainty); });
  (row.fix_records || []).forEach(function (fix) {
    add(detail, "p", "desc", "修复来源：" + fix.title + "；本系统未验证部署修复效果。");
    if (/^https:\/\//i.test(fix.url || "")) {
      var link = add(detail, "a", "", "查看修复记录");
      link.href = fix.url; link.target = "_blank"; link.rel = "noopener noreferrer";
    }
  });
  if ((row.poc_candidates || []).length) add(detail, "p", "hint", "存在 " + row.poc_candidates.length + " 条 PoC 候选引用，尚未由本系统运行验证。");
  if (!(row.evidence || []).length) add(detail, "p", "hint", "尚无足够的可引用版本证据，请查看研判任务中的未解决项。");
}

function renderRisks(data) {
  var target = $("risk-list"); clear(target);
  $("risk-summary").textContent = "当前筛选共 " + data.total + " 条资产与情报关联。待确认、结论过期均不能作为安全结论。";
  if (!data.items.length) add(target, "p", "empty", "暂无关联结果。请先登记资产，或等待相关研判完成；没有结果不代表没有风险。");
  data.items.forEach(function (row) {
    var card = add(target, "article", "asset-card");
    add(card, "h3", "", (row.asset.name || row.asset_id) + " · " + row.cve_id);
    add(card, "p", "desc", row.label + " · " + row.priority + " · " + row.disposition_label);
    add(card, "p", "meta", row.asset.product + " " + (row.asset.version || "版本未知") + " · 更新于 " + formatStamp(row.updated_at));
    add(card, "p", "desc", row.reason);
    renderRiskEvidence(card, row);
    var form = add(card, "form", "live-actions");
    form.addEventListener("input", function () { riskEditing = true; });
    form.addEventListener("change", function () { riskEditing = true; });
    var label = add(form, "label", "", "处置状态 ");
    var select = add(label, "select", "");
    Object.keys(dispositionLabels).forEach(function (value) {
      var option = add(select, "option", "", dispositionLabels[value]); option.value = value;
      if (value === "resolved" && row.status !== "not_matched") option.disabled = true;
      if (value === "accepted_risk" && row.status === "invalidated") option.disabled = true;
    });
    select.value = row.disposition;
    var noteLabel = add(form, "label", "", "处置依据 ");
    var note = add(noteLabel, "input", ""); note.maxLength = 1000; note.value = row.disposition_note || "";
    note.placeholder = "关闭或接受风险时必填";
    var save = add(form, "button", "ghost", "保存处置"); save.type = "submit";
    form.addEventListener("submit", function (event) {
      event.preventDefault(); save.disabled = true;
      api(riskPath(row) + "/disposition", {method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({status: select.value, note: note.value, expected_fingerprint: row.fingerprint})})
        .then(function () { riskEditing = false; return loadRisks(); }).catch(showError).finally(function () { save.disabled = false; });
    });
  });
  $("risk-prev").disabled = riskOffset === 0;
  $("risk-next").disabled = riskOffset + riskPageSize >= data.total;
  $("risk-page").textContent = "第 " + (Math.floor(riskOffset / riskPageSize) + 1) + " 页";
}

function renderInvestigations(data) {
  var target = $("investigation-list");
  var signature = JSON.stringify(data);
  if (signature === lastInvestigationRender) return;
  var opened = new Set(Array.from(target.children).filter(function (card) { return card.open; }).map(function (card) { return card._jobId; }));
  clear(target);
  lastInvestigationRender = signature;
  $("investigation-worker").textContent = data.worker_enabled ? "后台自动处理；本页每 10 秒更新一次。显示最近 50 项任务。" : "后台处理已关闭，排队任务不会执行。请在部署配置中启用自动处理。";
  if (!data.items.length) add(target, "p", "empty", "暂无研判任务。资产相关情报会自动创建任务，也可输入已收录的 CVE 主动研究。");
  data.items.forEach(function (job) {
    var card = add(target, "details", "asset-card"), trace = job.trace || {};
    card._jobId = String(job.id); card.open = opened.has(card._jobId);
    add(card, "summary", "", job.cve_id + " · " + (taskLabels[job.status] || job.status) + " · 尝试 " + job.attempts + " 次");
    add(card, "p", "hint", "触发：" + ({assets_changed: "资产清单变化", intelligence_updated: "情报新增或变化", user_research: "主动研究", manual_reassessment: "重新评估"}[job.context.reason] || job.context.reason || "后台核对"));
    if (trace.stop_reason) add(card, "p", "desc", "停止原因：" + (stopLabels[trace.stop_reason] || trace.stop_reason));
    if (trace.evidence_notice) add(card, "p", "hint", trace.evidence_notice);
    var gaps = trace.remaining_gaps || [];
    if (gaps.length) add(card, "p", "hint", "仍需确认：" + gaps.map(function (gap) { return gapLabels[gap] || gap; }).join("、"));
    (trace.decisions || []).forEach(function (decision) {
      add(card, "p", "desc", "步骤 " + decision.step + "：" + decision.tool + "（" + (decision.selected_by === "model" ? "模型选择" : "规则选择") + "）");
    });
    (trace.calls || []).forEach(function (call) {
      add(card, "p", "meta", call.tool + " · " + call.status + " · " + call.duration_ms + " ms");
    });
    if (job.error) add(card, "p", "hint", "执行状态：" + job.error);
    var historyButton = add(card, "button", "ghost", "查看历次执行"); historyButton.type = "button";
    var historyTarget = add(card, "div", "");
    historyButton.addEventListener("click", function () {
      historyButton.disabled = true;
      api("/api/investigations/" + job.id + "/runs").then(function (history) {
        clear(historyTarget);
        history.items.forEach(function (run) { add(historyTarget, "p", "meta", run.run_id + " · " + (taskLabels[run.status] || run.status) + " · " + (stopLabels[run.trace.stop_reason] || run.trace.stop_reason || "")); });
      }).catch(showError).finally(function () { historyButton.disabled = false; });
    });
  });
}

function loadRisks() {
  var request = ++riskRequest;
  var query = "?limit=" + riskPageSize + "&offset=" + riskOffset + "&status=" + encodeURIComponent($("risk-filter").value);
  return Promise.all([api("/api/risks" + query), api("/api/investigations")]).then(function (results) {
    if (request !== riskRequest) return;
    if (!riskEditing) renderRisks(results[0]);
    renderInvestigations(results[1]);
  });
}

on("risk-refresh", "click", function () { riskEditing = false; loadRisks().catch(showError); });
on("risk-filter", "change", function () { riskEditing = false; riskOffset = 0; loadRisks().catch(showError); });
on("risk-prev", "click", function () { riskEditing = false; riskOffset = Math.max(0, riskOffset - riskPageSize); loadRisks().catch(showError); });
on("risk-next", "click", function () { riskEditing = false; riskOffset += riskPageSize; loadRisks().catch(showError); });
on("risk-inventory", "click", function () { setView("enrich"); });
on("risk-reassess", "click", function () {
  var button = $("risk-reassess"); button.disabled = true;
  api("/api/risks/reassess", {method: "POST"}).then(function (data) { showToast("已安排 " + data.queued + " 项研判", "ok"); return loadRisks(); })
    .catch(showError).finally(function () { button.disabled = false; });
});
on("investigation-form", "submit", function (event) {
  event.preventDefault(); var button = $("investigation-submit"); button.disabled = true;
  api("/api/investigations/" + encodeURIComponent($("investigation-cve").value.trim().toUpperCase()), {method: "POST"})
    .then(function (data) { showToast(data.queued ? "主动调查已排队，将使用当前证据并按缺口补充；未完成富集不代表证据完整。" : "已有相同任务或此记录为演示数据", "ok"); return loadRisks(); })
    .catch(showError).finally(function () { button.disabled = false; });
});
setInterval(function () { if ($("risks") && !$("risks").hidden) loadRisks().catch(showError); }, 10000);
