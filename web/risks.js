/* Asset decisions and bounded research traces; all source text is rendered as text. */
var riskOffset = 0;
var riskPageSize = 30;
var riskRequest = 0;
var riskEditing = false;
var lastInvestigationRender = "";
var investigationOffset = 0;
var investigationPageSize = 30;
var investigationSubmitting = false;
var taskLabels = {pending: "排队中", running: "已领取（执行租约）", retry: "等待重试", done: "已完成", failed: "失败待处理", skipped: "输入已变化，旧任务跳过"};
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
  $("risk-summary").textContent = "当前筛选共 " + data.total + " 条资产与情报关联。" + ((data.automatic_matching || {}).running ? "自动判断运行中：新情报和资产变化后自动更新，无需选择 CVE。" : "自动判断状态请检查服务是否启动。") + "待确认、结论过期均不能作为安全结论。";
  if (!data.items.length) add(target, "p", "empty", "暂无关联结果。可点“载入并评估演示”查看完整示例；已有清单可在登记区即时评估并同步结果。");
  data.items.forEach(function (row) {
    var card = add(target, "article", "asset-card");
    add(card, "h3", "", (row.asset.name || row.asset_id) + " · " + row.cve_id);
    add(card, "p", "desc", row.label + " · " + row.priority + " · " + row.disposition_label);
    add(card, "p", "meta", row.asset.product + " " + (row.asset.version || "版本未知") + " · 更新于 " + formatStamp(row.updated_at));
    add(card, "p", "meta", "评估方式：" + ({automatic_rules: "自动版本匹配，Agent 后续补充证据", immediate_rules: "即时规则评估", agent_research: "Agent 证据研判"}[row.evaluation_mode] || "已保存评估"));
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
        .then(function () { riskEditing = false; if (typeof loadOverviewRisks === "function") loadOverviewRisks(); return loadRisks(); }).catch(showError).finally(function () { save.disabled = false; });
    });
  });
  $("risk-prev").disabled = riskOffset === 0;
  $("risk-next").disabled = riskOffset + riskPageSize >= data.total;
  $("risk-page").textContent = "第 " + (Math.floor(riskOffset / riskPageSize) + 1) + " 页";
}

function renderInvestigations(data) {
  var target = $("investigation-list");
  var worker = data.worker;
  var workerMessage;
  if (worker) {
    var workerLabels = {disabled: "后台处理已关闭", not_started: "后台处理已配置，但线程尚未启动", running: "后台处理正在运行", partial: "部分后台线程未运行", stopping: "后台处理正在停止", stopped: "后台处理已停止"};
    workerMessage = (workerLabels[worker.status] || "后台状态待确认") + "。资产自动研判：" + (worker.background && worker.background.running ? "运行中" : "未运行") + "；主动研判：" + (worker.explicit && worker.explicit.running ? "运行中" : "未运行") + "。";
    if (!worker.configured_enabled) workerMessage += "请在运行此服务的电脑设置 AUTO_INGEST_ON_COLLECT=1，并重启对应服务实例。";
    else if (worker.restart_required || worker.status === "not_started" || worker.status === "stopped") workerMessage += "请检查此服务实例的启动日志并重启，修改配置本身不会启动后台线程。";
  } else {
    workerMessage = data.worker_enabled ? "后台处理配置已启用，当前服务未提供线程运行状态。" : "后台处理已关闭，排队任务不会执行。请在运行此服务的电脑设置 AUTO_INGEST_ON_COLLECT=1，并重启对应服务实例。";
  }
  $("investigation-worker").textContent = workerMessage + " 本页每 10 秒更新。任务执行次数是后台领取该任务的次数，不是模型推理或工具调用次数。";
  var total = Number.isInteger(data.total) ? data.total : data.items.length;
  var offset = Number.isInteger(data.offset) ? data.offset : investigationOffset;
  $("investigation-summary").textContent = "共 " + total + " 项研判任务；当前显示 " + (data.items.length ? (offset + 1) + "–" + (offset + data.items.length) : "0") + " 项。可展开多项对照查看。";
  $("investigation-prev").disabled = offset === 0;
  $("investigation-next").disabled = offset + investigationPageSize >= total;
  $("investigation-page").textContent = "第 " + (Math.floor(offset / investigationPageSize) + 1) + " / " + Math.max(1, Math.ceil(total / investigationPageSize)) + " 页";
  // Worker heartbeats change between polls; only task content may replace loaded histories.
  var signature = JSON.stringify({items: data.items, worker_enabled: data.worker_enabled});
  if (signature === lastInvestigationRender) return;
  var opened = new Set(Array.from(target.children).filter(function (card) { return card.open; }).map(function (card) { return card._jobId; }));
  clear(target);
  lastInvestigationRender = signature;
  if (!data.items.length) add(target, "p", "empty", "暂无研判任务。资产相关情报会自动创建任务，也可输入已收录的 CVE 主动研究。");
  data.items.forEach(function (job) {
    var card = add(target, "details", "asset-card"), trace = job.trace || {};
    card._jobId = String(job.id); card.open = opened.has(card._jobId);
    var waitCode = (job.wait_reason || {}).code;
    var jobLabel = {execution_unconfirmed: "保留执行标记", execution_stopping: "停止中（保留执行标记）", lease_expired: "执行租约已过期"}[waitCode] || taskLabels[job.status] || job.status;
    add(card, "summary", "", job.cve_id + " · " + jobLabel + " · 任务执行 " + job.attempts + " 次");
    var reason = (job.context || {}).reason;
    add(card, "p", "hint", "触发：" + ({assets_changed: "资产清单变化", intelligence_updated: "情报新增或变化", user_research: "主动研究", manual_reassessment: "重新评估"}[reason] || reason || "后台核对"));
    if (job.wait_reason && job.wait_reason.label) add(card, "p", "hint", "当前状态：" + job.wait_reason.label);
    ((job.wait_reason || {}).prerequisites || []).forEach(function (dependency) {
      add(card, "p", "meta", "前置任务：" + ({fetch: "证据采集", documents: "资料抓取", enrich: "情报富集", index: "检索索引"}[dependency.stage] || dependency.stage) + " · " + (taskLabels[dependency.status] || dependency.status) + " · 执行 " + dependency.attempts + " 次");
    });
    if (!job.attempts) {
      add(card, "p", "hint", "尚未开始 Agent 研判；执行 0 次表示尚未被后台领取。" + (job.wait_reason ? "" : data.worker_enabled ? "等待后台领取任务。" : "后台处理关闭，队列正在等待启用。"));
    } else if (trace.calls || Number.isInteger(trace.model_calls)) {
      add(card, "p", "desc", "最近已保存轨迹：工具调用 " + (trace.calls || []).length + " 次 · 模型调用 " + (Number.isInteger(trace.model_calls) ? trace.model_calls : "未记录") + " 次");
    } else if (job.status !== "running") {
      add(card, "p", "hint", "尚无已保存的 Agent 工具轨迹，请查看执行状态与历次执行。");
    }
    if (job.status === "running") add(card, "p", "hint", "当前任务保留领取标记；当前执行的 Agent 轨迹将在执行结束后保存，已有轨迹可能来自上一次执行。");
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
        if (!history.items.length) add(historyTarget, "p", "hint", "暂无已保存的执行记录；排队任务需先由后台领取执行。");
        history.items.forEach(function (run) {
          var runTrace = run.trace || {};
          add(historyTarget, "p", "meta", run.run_id + " · " + (taskLabels[run.status] || run.status) + " · " + (stopLabels[runTrace.stop_reason] || runTrace.stop_reason || ""));
        });
      }).catch(showError).finally(function () { historyButton.disabled = false; });
    });
  });
}

function loadRisks() {
  var request = ++riskRequest;
  var query = "?limit=" + riskPageSize + "&offset=" + riskOffset + "&status=" + encodeURIComponent($("risk-filter").value);
  var taskQuery = "?limit=" + investigationPageSize + "&offset=" + investigationOffset;
  return Promise.all([api("/api/risks" + query), api("/api/investigations" + taskQuery)]).then(function (results) {
    if (request !== riskRequest) return;
    if (!riskEditing) renderRisks(results[0]);
    renderInvestigations(results[1]);
  });
}

on("risk-refresh", "click", function () { riskEditing = false; loadRisks().catch(showError); });
on("risk-filter", "change", function () { riskEditing = false; riskOffset = 0; loadRisks().catch(showError); });
on("risk-prev", "click", function () { riskEditing = false; riskOffset = Math.max(0, riskOffset - riskPageSize); loadRisks().catch(showError); });
on("risk-next", "click", function () { riskEditing = false; riskOffset += riskPageSize; loadRisks().catch(showError); });
on("investigation-prev", "click", function () { investigationOffset = Math.max(0, investigationOffset - investigationPageSize); loadRisks().catch(showError); });
on("investigation-next", "click", function () { investigationOffset += investigationPageSize; loadRisks().catch(showError); });
on("risk-inventory", "click", function () { setView("enrich"); });
on("risk-reassess", "click", function () {
  var button = $("risk-reassess"); button.disabled = true;
  api("/api/risks/reassess", {method: "POST"}).then(function (data) { showToast("已安排 " + data.queued + " 项研判", "ok"); return loadRisks(); })
    .catch(showError).finally(function () { button.disabled = false; });
});
function parseInvestigationCves(value) {
  if (value.length > 1500) throw new Error("输入内容过长，请最多提交 20 个 CVE。");
  var ids = Array.from(new Set(value.trim().toUpperCase().split(/[\s,，;；、]+/).filter(Boolean)));
  if (!ids.length) throw new Error("请输入至少一个已收录的 CVE 编号。");
  if (ids.length > 20) throw new Error("一次最多研究 20 个不同 CVE，请分批提交。");
  var invalid = ids.filter(function (id) { return !/^CVE-[0-9]{4}-[0-9]{4,7}$/.test(id); });
  if (invalid.length) throw new Error("CVE 格式有误：" + invalid.join("、") + "。请输入完整编号，以逗号、空格或换行分隔。");
  return ids;
}

on("investigation-form", "submit", async function (event) {
  event.preventDefault();
  if (investigationSubmitting) return;
  var target = $("investigation-submission"), ids;
  clear(target);
  try { ids = parseInvestigationCves($("investigation-cve").value); }
  catch (error) { add(target, "p", "hint", error.message); return; }
  var button = $("investigation-submit"), input = $("investigation-cve");
  button.disabled = true; input.disabled = true; investigationSubmitting = true;
  var progress = add(target, "p", "hint", "正在逐项提交 " + ids.length + " 个 CVE…");
  var results = add(target, "ul", ""), queued = 0, retained = [], failed = 0;
  try {
    for (var index = 0; index < ids.length; index += 1) {
      var id = ids[index];
      try {
        var data = await api("/api/investigations/" + encodeURIComponent(id), {method: "POST"});
        queued += data.queued ? 1 : 0;
        add(results, "li", "", id + (data.queued ? "：已排队，等待后台执行。" : "：已有相同任务或属于演示记录，未重复排队。"));
      } catch (error) {
        failed += 1; retained.push(id);
        add(results, "li", "hint", id + "：提交未确认，请核对任务列表后重试。" + (error.message || "请求失败"));
      }
      progress.textContent = "已处理 " + (index + 1) + " / " + ids.length + " 个编号。";
    }
    progress.textContent = "本批 " + ids.length + " 个不同 CVE，已排队 " + queued + " 项，未重复排队 " + (ids.length - queued - failed) + " 项，提交未确认 " + failed + " 项。排队成功后仍需后台执行，才会生成研判结果。";
    input.value = retained.join("\n");
    investigationOffset = 0;
    await loadRisks();
  } catch (error) { showError(error); }
  finally { button.disabled = false; input.disabled = false; investigationSubmitting = false; }
});
setInterval(function () { if ($("risks") && !$("risks").hidden) loadRisks().catch(showError); }, 10000);
