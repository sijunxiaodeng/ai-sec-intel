/* Acceptance uses server snapshots and text-only DOM rendering, never inferred scores. */
var acceptanceState = { summary: null, run: null, window: null, caseId: null, drafts: {}, summaryToken: 0, runToken: 0, windowToken: 0 };
var acceptanceKinds = {single_fact: "单事实", comparison: "比较", multi_hop: "多跳推理", multi_turn: "多轮问答", refusal: "拒答", other: "其他", enrichment: "富化事实"};
var acceptanceThresholds = {collected: "期限内采集", late: "迟到", missing: "到期未采", unknown: "时间或范围未知", not_due: "尚未到期", excluded: "排除"};
var acceptanceBlockers = {no_cases: "本组尚无题目", dataset_hash_missing: "缺少冻结题单摘要", dataset_case_manifest_missing: "缺少完整题号清单", source_hashes_missing: "来源摘要不完整", unclassified_cases: "仍有题目未确认题型", group_classification_not_frozen: "分组题型尚未随原始题单冻结", independent_human_reviews_incomplete: "按声明独立的人审尚未完整覆盖全部题目", public_development_dataset: "公开开发集不能替代独立验收证据"};

function acText(value) { return value == null ? "未提供" : typeof value === "object" ? JSON.stringify(value, null, 2) : String(value); }
function acRate(value) { return typeof value === "number" && Number.isFinite(value) ? (value * 100).toFixed(1) + "%" : "待验证"; }
function acCount(value) { return typeof value === "number" && Number.isFinite(value) ? String(value) : "未知"; }
function acSeconds(value) { return typeof value === "number" && Number.isFinite(value) ? (value >= 3600 ? (value / 3600).toFixed(2) + " 小时" : value.toFixed(2) + " 秒") : "未知"; }
function acStamp(value) { return value ? formatStamp(value) : "尚无记录"; }
function acStatus(id, message, error) { var el = $(id); el.textContent = message || ""; el.className = "ac-status" + (error ? " is-error" : ""); }
function acEmpty(parent, message) { return add(parent, "p", "ac-empty", message); }
function acButton(parent, label, action, cls) { var button = add(parent, "button", cls || "ghost", label); button.type = "button"; button.addEventListener("click", action); return button; }
function acLink(parent, label, path) { var link = add(parent, "a", "ac-link", label); link.href = path; link.setAttribute("download", ""); return link; }
function acPath(type, id, suffix) { return "/api/acceptance/" + type + "/" + encodeURIComponent(id) + (suffix || ""); }
function acMeta(parent, pairs) { var dl = add(parent, "dl", "ac-meta"); pairs.forEach(function (pair) { add(dl, "dt", "", pair[0]); add(dl, "dd", "", acText(pair[1])); }); return dl; }
function acDetails(parent, title, value) { var box = add(parent, "details", "ac-details"); add(box, "summary", "", title); add(box, "pre", "ac-text", acText(value)); return box; }
function acLimitDetails(parent, title, values) { return acDetails(parent, title, values.map(function (value) { return acceptanceBlockers[value] || value; }).join("\n")); }
function acTable(parent, headings, rows) {
  var wrap = add(parent, "div", "ac-table-wrap"), table = add(wrap, "table", "ac-table");
  var head = add(add(table, "thead"), "tr"); headings.forEach(function (label) { var th = add(head, "th", "", label); th.scope = "col"; });
  var body = add(table, "tbody"); rows.forEach(function (row) { var tr = add(body, "tr"); row.forEach(function (cell) { add(tr, "td", "", acText(cell)); }); });
}
function acRequest(path, payload) {
  var options = {cache: "no-store"};
  if (payload !== undefined) { options.method = "POST"; options.headers = {"Content-Type": "application/json"}; options.body = JSON.stringify(payload); }
  return fetch(path, options).then(function (response) {
    return response.json().catch(function () { return {detail: "服务端返回了无法解析的响应"}; }).then(function (data) {
      if (!response.ok) { var error = new Error(typeof data.detail === "string" ? data.detail : "请求失败（HTTP " + response.status + "）"); error.status = response.status; throw error; }
      return data;
    });
  });
}
function acBusy(form, busy) { form.querySelectorAll("button[type=submit]").forEach(function (button) { button.disabled = busy; button.setAttribute("aria-busy", String(busy)); }); }
function acReadJSON(input) {
  var file = input.files && input.files[0];
  if (!file) return Promise.reject(new Error("请选择 JSON 文件"));
  if (file.size > 8 * 1024 * 1024) return Promise.reject(new Error("JSON 文件不能超过 8 MiB"));
  return file.text().then(function (text) {
    var result;
    try { result = JSON.parse(text.replace(/^\uFEFF/, "")); } catch (error) { throw new Error("JSON 格式无效，请检查文件内容"); }
    if (!result || Array.isArray(result) || typeof result !== "object") throw new Error("JSON 顶层须为对象");
    return result;
  });
}
function acSelectOptions(id, rows, key, preferred, emptyLabel) {
  var select = $(id), previous = preferred || select.value; clear(select);
  if (!rows.length) { var empty = add(select, "option", "", emptyLabel); empty.value = ""; select.value = ""; return ""; }
  rows.forEach(function (row) { var option = add(select, "option", "", (row.title || row.name || row[key]) + (row.run_at ? " · " + acStamp(row.run_at) : "")); option.value = row[key]; });
  select.value = rows.some(function (row) { return row[key] === previous; }) ? previous : rows[0][key];
  return select.value;
}
function loadAcceptance(options) {
  options = options || {}; var token = ++acceptanceState.summaryToken;
  acStatus("ac-status", "正在读取验收快照…");
  return acRequest("/api/acceptance/summary").then(function (data) {
    if (token !== acceptanceState.summaryToken) return;
    acceptanceState.summary = data;
    acStatus("ac-status", "快照生成于 " + acStamp(data.generated_at) + " · 时间显示为北京时间 · 点击“更新快照”读取最新证据");
    acRenderCriteria(data); acRenderRuntime(data); acRenderEvidence();
    clear($("ac-method")); (data.method || []).forEach(function (line) { add($("ac-method"), "li", "", line); });
    var run = acSelectOptions("ac-run-select", data.quality_runs || [], "run_id", options.runId, "尚无评测批次");
    var observation = acSelectOptions("ac-window-select", data.observation_windows || [], "id", options.windowId, "尚无观察窗口");
    var requests = [];
    if (run && (!acceptanceState.run || acceptanceState.run.run_id !== run || options.refreshDetails)) requests.push(acLoadRun(run));
    if (!run) { clear($("ac-quality-summary")); acEmpty($("ac-quality-summary"), "尚未导入评测。可以先下载模板，冻结完整题单与实际输出后导入。"); $("ac-quality-workspace").hidden = true; }
    if (observation && (!acceptanceState.window || acceptanceState.window.id !== observation || options.refreshDetails)) requests.push(acLoadWindow(observation));
    if (!observation) { clear($("ac-observation-detail")); acEmpty($("ac-observation-detail"), "尚未启动观察。创建窗口后，后台按真实采集记录持续保存证据，关闭此页面也不会停止观察。"); }
    return Promise.all(requests);
  }).catch(function (error) { if (token === acceptanceState.summaryToken) acStatus("ac-status", "验收快照读取失败：" + error.message, true); });
}
function acRenderCriteria(data) {
  var parent = $("ac-criteria"); clear(parent);
  (data.criteria || []).forEach(function (criterion) {
    var card = add(parent, "div", "ac-criterion"), head = add(card, "div", "ac-criterion-head");
    add(head, "h3", "", criterion.title); add(head, "span", "ac-weight", "权重 " + acCount(criterion.weight) + "%");
    add(card, "p", "ac-target", "目标｜" + acText(criterion.target));
    add(card, "span", "ac-badge" + (criterion.status === "pending" ? " pending" : ""), criterion.status_label || "待验证");
    add(card, "p", "ac-observed", "现状｜" + acText(criterion.observed));
    acButton(card, "查看证据", function () {
      var anchor = {quality: "ac-quality", observation: "ac-observation", evidence: "ac-evidence"}[criterion.view];
      if (anchor) $(anchor).scrollIntoView({behavior: "smooth", block: "start"});
      else if (["monitor", "enrich", "ask", "risks"].indexOf(criterion.view) >= 0) setView(criterion.view);
    });
  });
}
function acRenderRuntime(data) {
  var parent = $("ac-runtime"), runtime = data.runtime || {}, observer = data.observer || {}; clear(parent);
  var chips = add(parent, "div", "ac-chips");
  (runtime.source_categories || []).forEach(function (row) { add(chips, "span", "", row.label + " · " + (row.sources || []).length + " 源"); });
  add(parent, "p", "hint", runtime.source_scope_note || "来源范围待核对");
  var fields = runtime.field_coverage;
  if (fields) { acTable(parent, ["富化字段", "非空记录", "字段存在率"], Object.keys(fields.counts || {}).map(function (key) {
    return [key, acCount(fields.counts[key]), fields.live_records > 0 ? acRate(fields.counts[key] / fields.live_records) : "待验证"];
  })); add(parent, "p", "hint", fields.note); }
  acMeta(parent, [["调查运行", acCount(runtime.agent_runs)], ["模型复核运行", acCount(runtime.model_review_runs)], ["观察器", observer.running ? "运行中" : "未运行或状态未知"], ["最近观察器心跳", acStamp(observer.last_tick_at)], ["观察器说明", observer.note || "未提供"]]);
  if ((runtime.processing || []).length) acTable(parent, ["处理阶段", "状态", "任务数"], runtime.processing.map(function (row) { return [row.stage, row.status, acCount(row.count)]; }));
  (runtime.errors || []).concat(observer.last_error ? [observer.last_error] : []).forEach(function (error) { add(parent, "p", "ac-status is-error", error); });
}
function acLoadRun(id) {
  var token = ++acceptanceState.runToken; acStatus("ac-quality-status", "正在读取评测…");
  return acRequest(acPath("quality", id)).then(function (run) {
    if (token !== acceptanceState.runToken || $("ac-run-select").value !== id) return;
    acceptanceState.run = run;
    if (!(run.cases || []).some(function (row) { return row.id === acceptanceState.caseId; })) acceptanceState.caseId = run.cases && run.cases[0] ? run.cases[0].id : null;
    acStatus("ac-quality-status", "原始报告已冻结；复核以追加历史保存。已编辑草稿保留原版本，冲突时需先查看最新复核。");
    acRenderQuality(); acRenderCases(); acRenderCase();
  }).catch(function (error) { if (token === acceptanceState.runToken) acStatus("ac-quality-status", "评测读取失败：" + error.message, true); });
}
function acRenderQuality() {
  var run = acceptanceState.run, stats = run.statistics || {}, parent = $("ac-quality-summary"); clear(parent);
  var visibility = {public_development: "公开开发集（不视为独立验收集）", held_out: "留出评测集（由导入者声明）", unspecified: "数据集属性未说明"};
  add(parent, "span", "ac-badge pending", visibility[run.dataset_visibility] || "数据集属性未说明");
  acMeta(parent, [["实际运行时间", acStamp(run.run_at)], ["导入时间", acStamp(run.imported_at)], ["评测代码提交", run.source_commit || "未登记（版本未知）"], ["模型 / 模式", acText(run.model) + " / " + acText(run.mode)], ["记录用途", run.purpose === "acceptance" ? "验收记录（不改变数据集属性）" : "开发验证"], ["统计单元", run.evaluation_unit === "fact_unit" ? "事先确定的富化事实单元" : "题目"], ["原始题单 SHA-256", run.dataset_sha256 || "未提供"], ["来源摘要", run.source_hashes_complete ? "摘要字段齐全（未重新请求来源；内容正确性仍需复核）" : "不完整 / 待核对"]]);
  add(parent, "p", "hint", "自动检查：通过 " + acCount(stats.automatic_passed) + " · 未通过 " + acCount(stats.automatic_failed) + " · 未检查 " + acCount(stats.automatic_unchecked) + "。这些是规则检查计数，不作为语义准确率。");
  var metricGroups = [["basic", "基础问答", "目标 ≥70%"], ["multi_hop", "明确多跳问答", "目标 ≥85%；仅统计冻结为 multi_hop 的题目"], ["enrichment", "富化事实", "目标 ≥70% / ≥85% / ≥95%"]].filter(function (item) {
    return ((stats.by_kind || {})[item[0]] || {}).cases > 0;
  });
  var grid = metricGroups.length ? add(parent, "div", "ac-metric-grid") : null;
  metricGroups.forEach(function (item) {
    var group = (stats.by_kind || {})[item[0]] || {}, card = add(grid, "div", "ac-metric");
    var types = group.reviewed_subset_by_reviewer_type || {};
    var aiOnly = Number(types.ai) > 0 && Number(types.human || 0) === 0;
    add(card, "h3", "", item[1]); add(card, "div", "ac-number", acRate(aiOnly ? group.reviewed_subset_accuracy : group.independent_accuracy));
    add(card, "p", "ac-number-label", aiOnly ? "AI辅助复核通过比例（非独立人审）" : "按声明独立复核准确率");
    add(card, "p", "hint", aiOnly ? "通过 " + acCount(group.reviewed_subset_passed) + " / " + acCount(group.reviewed_subset_denominator) + " 条冻结事实；可在下方追加人工复核。" : item[2]);
    add(card, "p", "hint", "复核覆盖 " + acCount(group.reviewed_cases) + " / " + acCount(group.cases) + "；未复核 " + acCount(group.unreviewed_cases));
    add(card, "p", "hint", "已有复核但必要检查未填完 " + acCount(group.incomplete_review_cases));
    add(card, "p", "hint", "复核子集准确率 " + acRate(group.reviewed_subset_accuracy) + "（分母 " + acCount(group.reviewed_subset_denominator) + "）");
    add(card, "p", "hint", "声明独立的人审 " + acCount(group.independent_reviewed_cases) + "；有效分母 " + acCount(group.independent_denominator));
    var interval = group.confidence_interval_95;
    if (interval) add(card, "p", "hint", "95% 区间 " + acRate(interval.lower) + "–" + acRate(interval.upper));
    if ((group.independent_blockers || []).length) acLimitDetails(card, "仍待满足的核验条件", group.independent_blockers);
  });
  var extraGroups = [["complex", "比较 / 多轮等复杂题"], ["other", "其他题型"]].filter(function (item) { return ((stats.by_kind || {})[item[0]] || {}).cases > 0; });
  if (extraGroups.length) {
    acTable(parent, ["补充题型", "题量", "已留复核记录", "复核子集准确率", "按声明独立复核准确率"], extraGroups.map(function (item) {
      var group = stats.by_kind[item[0]];
      return [item[1], acCount(group.cases), acCount(group.reviewed_cases), acRate(group.reviewed_subset_accuracy) + " / 分母 " + acCount(group.reviewed_subset_denominator), acRate(group.independent_accuracy) + " / 分母 " + acCount(group.independent_denominator)];
    }));
  }
  if (((stats.by_kind || {}).multi_hop || {}).cases > 0) add(parent, "p", "hint", "比较或普通多轮追问不自动算多跳；明确多跳需在冻结题单中登记其跨证据推理要求。");
  if ((stats.independent_blockers || []).length) acLimitDetails(parent, "本批次核验限制", stats.independent_blockers);
  var timing = stats.timing || {};
  acMeta(parent, [["完整批次题量", acCount(stats.cases)], ["尚未归类题量", acCount(stats.unclassified_cases)], ["模型使用", "尝试 " + acCount(stats.model_attempted_cases) + " 题 / 实际采用 " + acCount(stats.used_model_cases) + " 题"], ["响应耗时", "P95 " + acSeconds(timing.p95_seconds) + " / 最大 " + acSeconds(timing.max_seconds) + " / 有效样本 " + acCount(timing.sample_count)], ["超过 5 秒", acCount(timing.over_5_seconds) + " 题；这是性能记录，5 秒不是初赛硬性门槛"]]);
  var actions = add(parent, "div", "ac-actions"); acLink(actions, "导出完整报告与复核历史", acPath("quality", run.run_id, "/export"));
  acDetails(parent, "查看冻结原始报告", run.original_report);
  $("ac-quality-workspace").hidden = !(run.cases || []).length;
}
function acReviewValue(row) { return row && row.review ? row.review : row || {}; }
function acCaseMatches(row, filter, search) {
  var review = acReviewValue(row.latest_review);
  if (filter === "unreviewed" && row.latest_review) return false;
  if (filter === "automatic_failed" && row.automatic_passed !== false) return false;
  if (filter === "review_failed" && !["correct", "citations_supported", "conditions_preserved", "reasoning_valid"].some(function (key) { return review[key] === false; })) return false;
  return !search || (String(row.id) + " " + acText(row.question)).toLowerCase().indexOf(search.toLowerCase()) >= 0;
}
function acRenderCases() {
  var parent = $("ac-case-list"); clear(parent); var cases = (acceptanceState.run || {}).cases || [];
  var filtered = cases.filter(function (row) { return acCaseMatches(row, $("ac-case-filter").value, $("ac-case-search").value.trim()); });
  $("ac-case-count").textContent = "显示 " + filtered.length + " / " + cases.length + " 题；右侧保留当前查看题目。";
  if (!filtered.length) acEmpty(parent, "没有符合筛选条件的题目");
  filtered.forEach(function (row) {
    var button = acButton(parent, "", function () { acceptanceState.caseId = row.id; acRenderCases(); acRenderCase(); }, "ac-case-button");
    button.setAttribute("aria-pressed", String(row.id === acceptanceState.caseId));
    add(button, "strong", "", row.id + " · " + (row.latest_review ? "已复核" : "未复核"));
    add(button, "span", "", acText(row.question).slice(0, 115));
    add(button, "span", "", row.automatic_passed === true ? "自动检查通过" : row.automatic_passed === false ? "自动检查未通过" : "无自动检查结论");
  });
}
function acInput(parent, label, type, value) { var wrap = add(parent, "label", "", label), input = add(wrap, type === "textarea" ? "textarea" : "input"); if (type !== "textarea") input.type = type; input.value = value || ""; return input; }
function acSelect(parent, label, options, value) { var wrap = add(parent, "label", "", label), input = add(wrap, "select"); options.forEach(function (row) { var option = add(input, "option", "", row[1]); option.value = row[0]; }); input.value = value == null ? "" : value; return input; }
function acBool(value) { return value === true ? "yes" : value === false ? "no" : ""; }
function acCheck(value) { return value === "yes" ? true : value === "no" ? false : null; }
function acDraftKey(run, row) { return run.run_id + ":" + row.id; }
function acRenderCase() {
  var parent = $("ac-case-detail"), run = acceptanceState.run; clear(parent);
  var row = (run.cases || []).find(function (item) { return item.id === acceptanceState.caseId; });
  if (!row) { acEmpty(parent, "选择题目后查看原始输出、证据与复核表。"); return; }
  add(parent, "h3", "", row.id + " · " + acText(row.question));
  [["实际回答 / 富化输出", row.prediction], ["参考答案 / 参考事实", row.reference], ["上下文与来源证据", row.context]].forEach(function (item) { add(parent, "p", "ac-text-title", item[0]); add(parent, "pre", "ac-text", acText(item[1])); });
  add(parent, "p", "hint", "耗时 " + acSeconds(row.seconds) + " · 自动结果 " + (row.automatic_passed === true ? "通过" : row.automatic_passed === false ? "未通过" : "未检查"));
  if ((row.failures || []).length) acDetails(parent, "自动检查未通过项", row.failures);
  acDetails(parent, "完整响应与原始题目", {response: row.response, original_case: row.original_case});
  acDetails(parent, "复核历史（追加保留）", row.review_history || []);
  var key = acDraftKey(run, row), saved = acceptanceState.drafts[key], initial = saved || acReviewValue(row.latest_review);
  var form = add(parent, "form", "ac-form-grid ac-review-form"); add(form, "h3", "", "追加人工复核");
  var reviewer = acInput(form, "复核者姓名 / 标识", "text", initial.reviewer); reviewer.required = true; reviewer.maxLength = 160;
  var reviewerType = acSelect(form, "复核者类型", [["human", "人工"], ["ai", "AI 辅助复核（不计入独立人审）"]], initial.reviewer_type || "human");
  var kind = acSelect(form, row.reasoning_kind ? "题型（已随原题冻结）" : "题型（按真实推理任务确认）", [["", "请选择题型"]].concat(Object.keys(acceptanceKinds).map(function (item) { return [item, acceptanceKinds[item]]; })), row.reasoning_kind || initial.reasoning_kind || row.effective_reasoning_kind || (run.kind === "enrichment" ? "enrichment" : "")); kind.required = true; kind.disabled = Boolean(row.reasoning_kind);
  var independentLabel = add(form, "label", "ac-checkbox", ""), independent = add(independentLabel, "input"); independent.type = "checkbox"; independent.checked = initial.independent === true;
  add(independentLabel, "span", "", "我声明本次复核独立于题目开发与答案生成（系统不认证身份）");
  var checks = {}, choices = [["", "尚未核对 / 不适用"], ["yes", "通过"], ["no", "不通过"]];
  [["correct", "事实 / 答案正确"], ["citations_supported", "引用确实支持结论"], ["conditions_preserved", "前提、版本与适用条件保留"], ["reasoning_valid", "推理链有效（复杂题必核对）"]].forEach(function (item) { checks[item[0]] = acSelect(form, item[1], choices, acBool(initial[item[0]])); });
  var note = acInput(form, "复核说明 / 错误与证据定位", "textarea", initial.note); note.parentNode.className = "ac-wide";
  var message = add(form, "p", "ac-status ac-wide"); message.setAttribute("role", "status");
  var revision = saved ? saved.expected_revision : row.revision || 0;
  add(form, "p", "hint ac-wide", "未核对项不会按通过处理；基础题不强制推理链，复杂题需全部核对。姓名、独立性与标签都将留在历史中。草稿基于版本 " + revision + "。");
  var actions = add(form, "div", "ac-actions ac-wide"), submit = add(actions, "button", "primary", "保存本题复核"); submit.type = "submit";
  function payload() { var result = {reviewer: reviewer.value.trim(), reviewer_type: reviewerType.value, independent: independent.checked, reasoning_kind: kind.value, note: note.value, expected_revision: revision}; Object.keys(checks).forEach(function (name) { result[name] = acCheck(checks[name].value); }); return result; }
  function saveDraft() { acceptanceState.drafts[key] = payload(); }
  form.addEventListener("input", saveDraft); form.addEventListener("change", saveDraft);
  var conflictButton = acButton(actions, "查看最新复核并更新草稿版本", function () {
    conflictButton.disabled = true;
    acRequest(acPath("quality", run.run_id)).then(function (latest) {
      var current = (latest.cases || []).find(function (item) { return item.id === row.id; });
      if (!current) throw new Error("原题已不可读取");
      revision = current.revision || 0; saveDraft();
      acDetails(parent, "最新复核（请比较后再提交草稿）", current.latest_review || {});
      message.textContent = "已取得版本 " + revision + "。草稿已保留，请比较最新复核后再次保存；系统不会自动覆盖。";
      message.className = "ac-status ac-wide"; conflictButton.hidden = true;
    }).catch(function (error) { message.textContent = error.message; }).finally(function () { conflictButton.disabled = false; });
  }); conflictButton.hidden = true;
  form.addEventListener("submit", function (event) {
    event.preventDefault(); var body = payload();
    if (!body.reviewer || !body.reasoning_kind) { message.textContent = "请填写复核者并选择题型。"; message.className = "ac-status is-error ac-wide"; return; }
    saveDraft(); acBusy(form, true); message.textContent = "正在保存复核…";
    acRequest(acPath("quality", run.run_id, "/reviews/" + encodeURIComponent(row.id)), body).then(function () {
      // Typing while a request is pending must not erase a newer local draft.
      if (JSON.stringify(acceptanceState.drafts[key]) === JSON.stringify(body)) delete acceptanceState.drafts[key];
      if ($("ac-run-select").value === run.run_id) return acLoadRun(run.run_id);
    }).catch(function (error) {
      message.textContent = error.status === 409 ? "复核版本冲突：另一份复核已保存。当前草稿已保留，请先查看最新复核，再决定是否追加。" : "保存失败：" + error.message;
      message.className = "ac-status is-error ac-wide"; conflictButton.hidden = error.status !== 409;
    }).finally(function () { acBusy(form, false); });
  });
}
function acLoadWindow(id) {
  var token = ++acceptanceState.windowToken; acStatus("ac-observation-status", "正在读取观察快照…");
  return acRequest(acPath("observations", id)).then(function (record) {
    if (token !== acceptanceState.windowToken || $("ac-window-select").value !== id) return;
    acceptanceState.window = record; acStatus("ac-observation-status", "最近保存快照：" + acStamp(record.latest_snapshot_at) + " · 共 " + acCount(record.snapshots_count) + " 份快照"); acRenderWindow();
  }).catch(function (error) { if (token === acceptanceState.windowToken) acStatus("ac-observation-status", "观察读取失败：" + error.message, true); });
}
function acProgress(record) {
  var start = Date.parse(record.start_at), end = Date.parse(record.end_at), sampled = Date.parse(record.latest_snapshot_at);
  return Number.isFinite(start) && Number.isFinite(end) && Number.isFinite(sampled) && end > start ? Math.max(0, Math.min(100, (sampled - start) / (end - start) * 100)) : 0;
}
function acRenderThresholds(parent, title, metrics) {
  add(parent, "h3", "subhead", title);
  ["6", "12", "24"].forEach(function (hours) {
    var row = (metrics.by_threshold || {})[hours] || {}, group = add(parent, "div", "ac-threshold"), heading = add(group, "div", "ac-threshold-title");
    add(heading, "strong", "", hours + " 小时"); add(heading, "span", "", "期限内占比 " + acRate(row.within_rate) + " · 有效分母 " + acCount(row.denominator));
    var keys = Object.keys(acceptanceThresholds), total = keys.reduce(function (sum, key) { return sum + (typeof row[key] === "number" ? Math.max(0, row[key]) : 0); }, 0);
    var stack = add(group, "div", "ac-stack"); stack.setAttribute("aria-hidden", "true");
    if (total) keys.forEach(function (key) { var count = typeof row[key] === "number" ? Math.max(0, row[key]) : 0; if (count) { var segment = add(stack, "span", "ac-" + key); segment.style.width = (count / total * 100) + "%"; } });
    var legend = add(group, "div", "ac-legend"); keys.forEach(function (key) { var entry = add(legend, "span"); add(entry, "i", "ac-dot ac-" + key); add(entry, "span", "", acceptanceThresholds[key] + " " + acCount(row[key])); });
  });
}
function acSampleDetails(parent, title, items) {
  var detail = add(parent, "details", "ac-details"); add(detail, "summary", "", title + "（" + items.length + " 项）");
  var search = acInput(detail, "按来源或记录 ID 筛选", "search", ""), results = add(detail, "div"), page = 1, size = 20;
  function render() {
    clear(results); var query = search.value.trim().toLowerCase();
    var filtered = items.filter(function (row) { return !query || (row.source + " " + row.id).toLowerCase().indexOf(query) >= 0; });
    var pages = Math.max(1, Math.ceil(filtered.length / size)); page = Math.max(1, Math.min(page, pages));
    if (!filtered.length) { acEmpty(results, "没有匹配的来源记录"); return; }
    acTable(results, ["来源 / ID", "发布时间", "首次采集", "采集延迟", "6 / 12 / 24 小时", "判定理由"], filtered.slice((page - 1) * size, page * size).map(function (row) {
      return [row.source + " / " + row.id, acStamp(row.published_at), acStamp(row.first_seen_at), acSeconds(row.delay_seconds), ["6", "12", "24"].map(function (key) { return acceptanceThresholds[(row.thresholds || {})[key]] || "未知"; }).join(" / "), row.reason || (row.match_status === "matched" ? "已匹配采集记录" : row.match_status === "unmatched" ? "未匹配采集记录" : "未提供")];
    }));
    var actions = add(results, "div", "ac-actions"); add(actions, "span", "hint", "第 " + page + " / " + pages + " 页 · " + filtered.length + " 项");
    var previous = acButton(actions, "上一页", function () { page -= 1; render(); }); previous.disabled = page <= 1;
    var next = acButton(actions, "下一页", function () { page += 1; render(); }); next.disabled = page >= pages;
  }
  search.addEventListener("input", function () { page = 1; render(); }); render();
}
function acRenderWindow() {
  var record = acceptanceState.window, parent = $("ac-observation-detail"); clear(parent);
  var labels = {active: "72 小时观察中", maturing: "观察已结束 · 等待样本截止", ready: "观察结束 · 可冻结", frozen: "已冻结报告"};
  add(parent, "span", "ac-badge" + (record.status === "frozen" ? "" : " pending"), labels[record.status] || "状态未知");
  var track = add(parent, "div", "ac-time-track"), fill = add(track, "div", "ac-time-fill"), progress = acProgress(record); fill.style.width = progress.toFixed(2) + "%";
  track.setAttribute("role", "progressbar"); track.setAttribute("aria-label", "按最近真实快照计算的 72 小时观察进度"); track.setAttribute("aria-valuemin", "0"); track.setAttribute("aria-valuemax", "100"); track.setAttribute("aria-valuenow", progress.toFixed(1));
  add(parent, "p", "hint", "快照覆盖到观察时段的 " + progress.toFixed(1) + "%；这是采样时间位置，不代表样本覆盖率或成功率。");
  var versions = (record.versions_seen || []).map(function (version) { return version || "未登记（版本未知）"; });
  acMeta(parent, [["窗口开始", acStamp(record.start_at)], ["72 小时结束", acStamp(record.end_at)], ["迟到核对截止", acStamp(record.maturity_end_at)], ["有效证据截至", acStamp(record.evidence_as_of)], ["初始部署版本", record.source_commit || "未登记（版本未知）"], ["观察中见过版本", versions.length ? versions.join("；") : "尚无版本记录"], ["观察范围", record.scope], ["统计单元", "来源记录（同一内容跨来源分别计数）"], ["登记来源", (record.sources || []).join("、")]]);
  add(parent, "p", "hint", "初始版本随窗口冻结；后续版本来自实际采样，版本列表不表示精确部署时刻。未知版本会保留标识，不按当前版本补写历史。");
  var metrics = record.metrics || {}, observed = metrics.observed || {}, inventory = metrics.inventory || {}, coverage = record.coverage || {}, latency = observed.latency || {};
  var grid = add(parent, "div", "ac-metric-grid");
  [["已观察来源记录", acCount(observed.record_count), "纳入样本 " + acCount(observed.eligible_count)], ["发布到采集 P95", acSeconds(latency.p95_seconds), "有效时间样本 " + acCount(latency.samples)], ["清单匹配召回率", acRate(inventory.recall), "上游完整性尚未独立验证"]].forEach(function (item) { var card = add(grid, "div", "ac-metric"); add(card, "h3", "", item[0]); add(card, "div", "ac-number", item[1]); add(card, "p", "hint", item[2]); });
  add(parent, "p", "hint", "P50 " + acSeconds(latency.p50_seconds) + " · 最大延迟 " + acSeconds(latency.max_seconds) + "。缺少精确时间或范围的样本不作为准时成功；未到截止的样本保留等待状态。");
  acRenderThresholds(parent, "已观察记录的延迟分布", observed);
  if ((observed.items || []).length) acSampleDetails(parent, "已采集样本明细：发布时间、首次采集与延迟", observed.items);
  if (inventory.inventory_count > 0) { acRenderThresholds(parent, "上游清单核对（包括到期未采记录）", inventory); }
  else acEmpty(parent, "尚无上游清单。已观察记录仅能说明已采到样本的延迟，不能证明没有漏采；全量时效与召回率待验证。");
  acMeta(parent, [["清单登记", acCount(inventory.inventory_count) + " 份 / " + acCount(inventory.item_count) + " 项"], ["来源清单覆盖", inventory.source_coverage_complete ? "登记来源均有清单（完整性仍待核验）" : "尚未覆盖全部来源"], ["全量时效验证", inventory.sla_verified === true ? "服务端标记已验证" : "待验证"], ["快照心跳最大间隔", acSeconds(coverage.heartbeat_max_gap_seconds)], ["缺失心跳间隔", acCount(coverage.missing_heartbeat_intervals)], ["数据库读取失败", acCount(coverage.database_failures)], ["最近数据库读取", {ok: "成功", failed: "失败", unavailable: "数据库不可用", not_sampled: "尚未采样"}[coverage.latest_database_status] || "状态未知"]]);
  add(parent, "h3", "subhead", "来源运行状态");
  if ((coverage.source_run_history || []).length) acTable(parent, ["来源", "总轮数", "成功", "部分成功", "失败", "最近运行", "最大轮次间隔"], coverage.source_run_history.map(function (row) { return [row.source, row.runs, row.success, row.partial, row.failed, acStamp(row.last_run_at), acSeconds(row.max_run_gap_seconds)]; }));
  else acEmpty(parent, "尚无来源运行记录；不会将空记录解释为成功。");
  add(parent, "p", "hint", "来源轮次间隔与数据库快照心跳分别统计；部分成功保留已校验记录，同时保留未完成状态。");
  if ((record.inventories || []).length) acTable(parent, ["已登记清单", "条目", "获取时间", "覆盖起止", "完整性声明"], record.inventories.map(function (row) { return [row.source, row.item_count, acStamp(row.captured_at), acStamp(row.coverage_start) + " — " + acStamp(row.coverage_end), row.completeness_declaration ? "声明完整（未认证）" : "未声明完整"]; }));
  if ((inventory.items || []).length) acSampleDetails(parent, "逐项查看上游清单与匹配状态", inventory.items);
  acDetails(parent, "观察原始统计与排除理由", {coverage: coverage, excluded: observed.excluded, frozen_sha256: record.frozen_sha256});
  var actions = add(parent, "div", "ac-actions"); acLink(actions, record.status === "frozen" ? "下载冻结观察报告" : "导出当前进度快照（非最终报告）", acPath("observations", record.id, "/export"));
  var freeze = acButton(actions, "冻结观察报告", function () {
    freeze.disabled = true; acStatus("ac-observation-status", "正在冻结已有观测证据…");
    acRequest(acPath("observations", record.id, "/freeze"), {}).then(function () { if ($("ac-window-select").value === record.id) return acLoadWindow(record.id); }).catch(function (error) { if ($("ac-window-select").value === record.id) acStatus("ac-observation-status", "冻结失败：" + error.message, true); freeze.disabled = false; });
  }); freeze.disabled = ["ready", "maturing"].indexOf(record.status) < 0;
  if (record.status !== "frozen") add(parent, "p", "hint", "冻结是不可覆盖的最终快照；72 小时结束且有真实观察证据后才可操作。等待未到期样本成熟可获得更完整的 6/12/24 小时判定。");
  else acMeta(parent, [["冻结报告 SHA-256", record.frozen_sha256]]);
  $("ac-inventory-panel").hidden = record.status === "frozen";
}
function acRenderEvidence() {
  var parent = $("ac-evidence-list"), rows = (acceptanceState.summary || {}).evidence || [], search = $("ac-evidence-search").value.toLowerCase().trim(); clear(parent);
  var filtered = rows.filter(function (row) { return !search || [row.title, row.filename, row.kind, row.source_commit].join(" ").toLowerCase().indexOf(search) >= 0; });
  $("ac-evidence-count").textContent = "显示 " + filtered.length + " / " + rows.length + " 份";
  if (!filtered.length) acEmpty(parent, rows.length ? "没有匹配的材料" : "尚未登记可下载材料；页面不自动把任意本机文件当作验收证据。");
  filtered.forEach(function (row) {
    var card = add(parent, "div", "ac-evidence-card"); add(card, "h3", "", row.title || row.filename);
    add(card, "p", "hint", acText(row.kind) + " · " + acText(row.filename) + " · " + (typeof row.bytes === "number" ? (row.bytes / 1024).toFixed(1) + " KiB" : "大小未知"));
    if (row.note) add(card, "p", "hint", row.note);
    acDetails(card, "版本、时间与文件摘要", {source_commit: row.source_commit, captured_at: row.captured_at, sha256: row.sha256});
    if (row.available) acLink(card, "下载已登记材料", acPath("evidence", row.id, "/download"));
    else add(card, "span", "ac-badge pending", "登记文件暂不可用");
  });
}
on("ac-refresh", "click", function () { loadAcceptance({refreshDetails: true}); });
on("ac-run-select", "change", function () { if (this.value) acLoadRun(this.value); });
on("ac-window-select", "change", function () { if (this.value) acLoadWindow(this.value); });
on("ac-case-filter", "change", acRenderCases);
on("ac-case-search", "input", acRenderCases);
on("ac-evidence-search", "input", acRenderEvidence);
on("ac-quality-import", "submit", function (event) {
  event.preventDefault(); var form = this; acBusy(form, true); acStatus("ac-quality-status", "正在导入冻结报告…");
  acReadJSON($("ac-quality-file")).then(function (file) {
    return acRequest("/api/acceptance/quality/import", {title: $("ac-quality-title").value.trim() || file.title || undefined, purpose: $("ac-quality-purpose").value, source_commit: file.source_commit || undefined, report: file.report || file});
  }).then(function (run) { $("ac-quality-file").value = ""; return loadAcceptance({runId: run.run_id, refreshDetails: true}); }).catch(function (error) { acStatus("ac-quality-status", "导入失败：" + error.message, true); }).finally(function () { acBusy(form, false); });
});
on("ac-window-create", "submit", function (event) {
  event.preventDefault(); var form = this; acBusy(form, true); acStatus("ac-observation-status", "正在登记 72 小时窗口…");
  var payload = {name: $("ac-window-name").value.trim() || undefined, sources: []}; if ($("ac-window-scope").value.trim()) payload.scope = $("ac-window-scope").value.trim();
  acRequest("/api/acceptance/observations", payload).then(function (record) { return loadAcceptance({windowId: record.id, refreshDetails: true}); }).catch(function (error) { acStatus("ac-observation-status", "创建失败：" + error.message, true); }).finally(function () { acBusy(form, false); });
});
on("ac-inventory-import", "submit", function (event) {
  event.preventDefault(); var form = this, record = acceptanceState.window; if (!record) return; acBusy(form, true); acStatus("ac-observation-status", "正在核对并导入上游清单…");
  acReadJSON($("ac-inventory-file")).then(function (payload) { return acRequest(acPath("observations", record.id, "/inventory"), payload); }).then(function () { $("ac-inventory-file").value = ""; if ($("ac-window-select").value === record.id) return acLoadWindow(record.id); }).catch(function (error) { if ($("ac-window-select").value === record.id) acStatus("ac-observation-status", "清单导入失败：" + error.message, true); }).finally(function () { acBusy(form, false); });
});
