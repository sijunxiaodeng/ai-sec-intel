var titles = {
  overview: "总览",
  monitor: "情报监测",
  enrich: "情报富化",
  assets: "资产影响",
  ask: "情报问答",
  settings: "模型设置"
};

var prompts = [
  "CVE-2024-37032 的受影响版本是什么，如何修复？有没有修复记录？",
  "CVE-2025-0312 的风险有多高？影响哪个版本？",
  "ollama 相关漏洞里，哪些写了受影响版本？",
  "当前记录有没有被标成 Exploit 的链接？"
];

function $(id) {
  return document.getElementById(id);
}

function api(path, options) {
  return fetch(path, options).then(function (response) {
    return response.json().then(function (data) {
      if (!response.ok) {
        var detail = data && data.detail ? data.detail : "请求失败";
        if (Array.isArray(detail)) detail = "字段校验未通过：" + detail.slice(0, 3).map(function (row) { return (row.loc || []).slice(1).join(".") + "：" + row.msg; }).join("；");
        throw new Error(typeof detail === "string" ? detail : "请求失败");
      }
      return data;
    });
  });
}

function showError(error) {
  var banner = $("banner");
  banner.hidden = false;
  banner.textContent = error.message || "请求失败";
}

function clearError() {
  $("banner").hidden = true;
}

function scoreClass(score) {
  if (score == null) return "";
  if (score >= 7) return "high";
  if (score >= 4) return "mid";
  return "low";
}

function scoreText(score) {
  return score == null ? "原文没有" : String(score);
}

function dateText(value) {
  return (value || "").slice(0, 10) || "未知";
}

function epssText(epss) {
  if (!epss) return "尚未查询";
  if (epss.status === "ok") return String(epss.score);
  if (epss.status === "empty") return "公开源未收录";
  if (epss.status === "error") return "查询失败";
  return "尚未查询";
}

function kevText(kev) {
  if (!kev) return "尚未查询";
  if (kev.status === "listed") return "已列入" + (kev.date_added ? "，" + kev.date_added : "");
  if (kev.status === "not_listed") return "未列入";
  if (kev.status === "error") return "查询失败";
  return "尚未查询";
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function add(parent, tag, className, text) {
  var node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  parent.appendChild(node);
  return node;
}

function renderSteps(target, steps) {
  clear(target);
  if (!steps || !steps.length) {
    add(target, "p", "empty", "还没有运行记录。可以先去做一次监测或提问。");
    return;
  }
  steps.forEach(function (step) {
    var row = add(target, "div", "step");
    add(row, "div", "role", step.role);
    var body = add(row, "div");
    add(body, "div", "title", step.action);
    add(body, "div", "meta", step.detail);
  });
}

function renderItemRow(parent, item, onPick) {
  var row = add(parent, "button", "row");
  row.type = "button";
  row.addEventListener("click", function () { onPick(item.cve_id); });
  var id = add(row, "div");
  add(id, "div", "title", item.cve_id);
  add(id, "div", "meta", (item.sources || [item.source || ""]).join("、"));
  add(row, "div", "score " + scoreClass(item.cvss), scoreText(item.cvss));
  var text = add(row, "div");
  add(text, "div", "desc", (item.description || "").slice(0, 140));
  add(text, "div", "meta", dateText(item.published_at) + " · " + (item.source || ""));
}

function setPill(ready) {
  var pill = $("llm-pill");
  pill.textContent = ready ? "大模型已配置" : "大模型未配置，问答先摘录原文";
}

function setView(name) {
  clearError();
  Object.keys(titles).forEach(function (key) {
    $(key).hidden = key !== name;
  });
  document.querySelectorAll(".nav button").forEach(function (button) {
    button.className = button.getAttribute("data-view") === name ? "is-on" : "";
  });
  $("page-title").textContent = titles[name];
  if (name === "overview") loadOverview();
  if (name === "monitor" || name === "enrich") loadItems(name);
  if (name === "ask") loadAsk();
  if (name === "assets") loadAssets().catch(showError);
  if (name === "settings") loadSettings();
}

function loadOverview() {
  api("/api/overview").then(function (data) {
    setPill(data.llm_ready);
    var stats = $("stats");
    clear(stats);
    var monitor = data.monitor || {};
    $("monitor-line").textContent =
      "自动监测已启动，间隔 " + (monitor.interval_hours || 6) +
      " 小时，开始于 " + dateText(monitor.started_at) +
      "。可计时效的新漏洞 " + data.latency_count +
      " 条。更早公布的记录只用于演示。当前来源：" +
      ((data.sources || []).join("、") || "还没有");
    [
      [String(data.items), "知识库情报"],
      [String(data.source_count || 0), "已接入来源"],
      [String(data.latency_count || 0), "可计时效"],
      [data.llm_ready ? "可用" : "未配置", "问答模型"]
    ].forEach(function (pair) {
      var card = add(stats, "div", "stat");
      add(card, "b", "", pair[0]);
      add(card, "span", "", pair[1]);
    });
    var recent = $("recent");
    clear(recent);
    if (!data.recent.length) {
      add(recent, "p", "empty", "知识库还是空的。到情报监测里运行一次。");
    }
    data.recent.forEach(function (item) {
      renderItemRow(recent, item, function (id) { openDetail(id); });
    });
    renderSteps($("steps"), data.steps);
  }).catch(showError);
}

function loadItems(view) {
  var query = view === "monitor" ? $("filter").value.trim() : "";
  api("/api/items" + (query ? "?q=" + encodeURIComponent(query) : "")).then(function (data) {
    var target = view === "monitor" ? $("monitor-list") : $("enrich-list");
    clear(target);
    if (!data.items.length) {
      add(target, "p", "empty", "没有匹配的情报。");
      return;
    }
    data.items.forEach(function (item) {
      renderItemRow(target, item, function (id) { openDetail(id); });
    });
  }).catch(showError);
}

function openDetail(cveId) {
  setView("enrich");
  api("/api/items/" + encodeURIComponent(cveId)).then(renderDetail).catch(showError);
}

function renderAssessment(panel, report) {
  if (!report) return;
  var section = add(panel, "div", "assessment");
  add(section, "h3", "", "自动富化与影响评估");
  if (report.status !== "ok" && report.status !== "partial") {
    add(section, "p", "meta", report.detail || "评估证据不足，请先抓取关联资料。");
    return;
  }
  var metric = report.cvss;
  if (metric) {
    var levels = {NONE: "无", LOW: "低", MEDIUM: "中", HIGH: "高", CRITICAL: "严重"};
    fact("CVSS " + metric.version + " · " + metric.score + " · " + (levels[metric.severity] || metric.severity || "等级未提供"), metric.evidence_ids);
    add(section, "p", "meta", "评分提供者：" + (metric.source || "未提供") + " · 记录类型：" + (metric.metric_type || "未提供"));
    add(section, "p", "desc", metric.vector || "来源未提供向量");
  }
  (report.cvss_candidates || []).slice(1).forEach(function (row) {
    fact("其他来源评分：CVSS " + row.version + " · " + row.score + "；提供者 " + (row.source || "未提供") + "；类型 " + (row.metric_type || "未提供"), row.evidence_ids);
  });
  function fact(text, ids) {
    var block = add(section, "div", "field");
    add(block, "p", "desc", text);
    (ids || []).forEach(function (id) {
      var evidence = (report.evidence || []).find(function (row) { return row.citation_id === id; });
      if (!evidence) return;
      var link = add(block, "a", "meta", "证据：" + id);
      link.href = evidence.url; link.target = "_blank"; link.rel = "noopener";
      add(block, "p", "meta", evidence.locator);
    });
  }
  (report.affected_ranges || []).forEach(function (row) { fact("受影响组件范围：" + row.display, row.evidence_ids); });
  (report.attack_conditions || []).concat(report.technical_impact || []).forEach(function (row) { fact("评分向量解释 · " + row.label + "：" + row.text, row.evidence_ids); });
  (report.fix_records || []).forEach(function (row) { fact("修复记录：" + row.title + "；修复效果尚未由本项目测试。", row.evidence_ids); });
  (report.poc_candidates || []).forEach(function (row) { fact("利用代码候选：" + row.url + "；本项目未运行复现。", row.evidence_ids); });
  add(section, "p", "desc", "此技术报告未进行资产匹配；登记清单后，在「资产影响」查看筛选结果。");
  (report.warnings || []).forEach(function (warning) { add(section, "p", "meta", warning); });
  if (report.source) add(section, "p", "meta", "报告依据获取于 " + dateText(report.source.retrieved_at) + " 的来源快照。");
}

function renderDetail(item) {
  var panel = $("enrich-detail");
  clear(panel);
  add(panel, "h2", "", item.cve_id);
  add(panel, "p", "desc", item.description || "");
  var fields = add(panel, "div", "fields");
  [
    ["来源", (item.sources || []).join("、") || "原文没有"],
    ["产品", item.product || "原文没有"],
    ["受影响版本", (item.affected || []).join("、") || "原文没有"],
    ["CVSS", scoreText(item.cvss) + (item.severity ? " · " + item.severity : "")],
    ["CVSS 版本", item.cvss_version || "原文没有"],
    ["EPSS", epssText(item.epss)],
    ["CISA KEV", kevText(item.kev)],
    ["公开利用链接", item.poc_count ? item.poc_count + " 条链接" : "原文没有标记"],
    ["论文", item.paper_count ? item.paper_count + " 篇" : "尚未关联"]
  ].forEach(function (pair) {
    var field = add(fields, "div", "field");
    add(field, "span", "", pair[0]);
    add(field, "b", "", pair[1]);
  });
  renderAssessment(panel, item.assessment);
  var assetButton = add(panel, "button", "ghost", "查看登记资产影响");
  assetButton.type = "button";
  assetButton.addEventListener("click", function () {
    setView("assets");
    loadAssets(item.cve_id).then(function () { return evaluateSavedAssets(); }).catch(showError);
  });
  var links = add(panel, "div", "links");
  (item.papers || []).forEach(function (paper) {
    var link = add(links, "a", "", "论文：" + (paper.title || paper.url));
    link.href = paper.url;
    link.target = "_blank";
    link.rel = "noopener";
  });
  (item.references || []).forEach(function (url) {
    var link = add(links, "a", "", url);
    link.href = url;
    link.target = "_blank";
    link.rel = "noopener";
  });
  var nvd = add(links, "a", "", "打开来源页面");
  nvd.href = item.url;
  nvd.target = "_blank";
  nvd.rel = "noopener";
  var fetchButton = add(panel, "button", "", "抓取关联资料");
  fetchButton.type = "button";
  var statusBox = add(panel, "div", "links");
  function showDocuments(rows) {
    clear(statusBox);
    (rows || []).forEach(function (doc) {
      var block = add(statusBox, "div", "field");
      var labels = {vulnerability_record: "漏洞记录", direct_analysis: "漏洞分析", fix_record: "修复记录", poc_candidate: "利用代码候选（未执行）", background: "背景资料（不进入问答）"};
      add(block, "b", "", doc.status === "error" ? "抓取失败" : (labels[doc.relation_type] || "关联资料"));
      var errorText = "来源暂时无法读取，可以稍后重试。";
      if (/timed out|timeout/i.test(doc.error || "")) errorText = "连接超时，可以稍后重试。";
      if (/没有可用|暂不支持/.test(doc.error || "")) errorText = "未提取到可用正文，或暂不支持此文档格式。";
      add(block, "p", "meta", doc.association_reason || (doc.status === "error" ? errorText : ""));
      add(block, "p", "meta", "尝试时间：" + dateText(doc.retrieved_at) + " · 片段 " + (doc.chunks || 0) + (doc.retained_previous ? " · 保留上次成功证据：" + dateText(doc.last_success_at) : ""));
      var link = add(block, "a", "", doc.url);
      link.href = doc.url;
      link.target = "_blank";
      link.rel = "noopener";
    });
  }
  showDocuments(item.documents);
  fetchButton.addEventListener("click", function () {
    fetchButton.disabled = true;
    fetchButton.textContent = "正在抓取关联资料…";
    clearError();
    api("/api/documents", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({cve_id: item.cve_id})}).then(function (data) {
      showDocuments(data.documents);
      fetchButton.textContent = "本次成功 " + data.ok + "/" + data.attempted + " 个来源；" + (data.index.status === "ok" ? "索引已更新" : "使用原文词法检索");
      return api("/api/assessment/" + encodeURIComponent(item.cve_id)).then(function (report) {
        var previous = panel.querySelector(".assessment");
        renderAssessment(panel, report);
        if (previous) previous.replaceWith(panel.lastElementChild);
      });
    }).catch(showError).then(function () { fetchButton.disabled = false; });
  });
}

var exposureLabels = {internet: "互联网可达", internal: "内网", isolated: "隔离", unknown: "暴露信息未知"};
var authLabels = {required: "已登记需认证", none: "已登记无认证", unknown: "认证信息未知"};

function inventorySummary(asset) {
  return asset.vendor + "/" + asset.product + " · " + (asset.version || "版本未知") + " · " + exposureLabels[asset.exposure] + " · " + authLabels[asset.authentication];
}

function loadAssets(selected) {
  return Promise.all([api("/api/assets"), api("/api/items")]).then(function (data) {
    var inventory = data[0], select = $("asset-cve"), current = selected || select.value;
    clear(select);
    add(select, "option", "", "请选择 CVE").value = "";
    (data[1].items || []).forEach(function (item) { add(select, "option", "", item.cve_id).value = item.cve_id; });
    select.value = current;
    $("asset-count").textContent = inventory.count + " 条，其中演示资产 " + inventory.demo_count + " 条";
    clear($("asset-list"));
    if (!inventory.count) add($("asset-list"), "p", "empty", "暂无已保存资产。可填入演示清单预览，或登记实际组件。");
    (inventory.items || []).forEach(function (asset) {
      var block = add($("asset-list"), "div", "asset-card");
      add(block, "b", "", asset.name + (asset.is_demo ? "（演示资产）" : ""));
      add(block, "p", "meta", asset.asset_id + " · " + inventorySummary(asset));
      add(block, "p", "meta", "登记时间：" + dateText(asset.recorded_at));
    });
  }).catch(showError);
}

function assetPayload() {
  var text = $("asset-json").value.trim();
  if (!text) throw new Error("请先填写资产清单或填入演示内容。");
  var payload;
  try { payload = JSON.parse(text); } catch (error) { throw new Error("资产 JSON 格式不正确，请检查引号、逗号和括号。"); }
  if (!payload || !Array.isArray(payload.assets)) throw new Error("请使用包含 assets 数组的 JSON 对象。");
  return payload;
}

function selectedAssetCve() {
  var cve = $("asset-cve").value;
  if (!cve) throw new Error("请先选择用于匹配的 CVE 编号。");
  return cve;
}

function renderAssetImpact(report) {
  var target = $("asset-impact");
  clear(target);
  add(target, "p", "title", report.cve_id + " · " + (report.preview ? "输入内容预览，尚未保存" : "已保存清单评估"));
  add(target, "p", "desc", "版本命中 " + report.counts.matched_version + " · 待确认 " + report.counts.unknown + " · 未命中当前范围 " + report.counts.not_matched + "；演示资产 " + report.demo_count + " 条");
  if (!report.asset_count) add(target, "p", "empty", "尚未登记资产，无法评估具体组件。");
  (report.results || []).forEach(function (result) {
    var asset = result.asset, block = add(target, "div", "asset-card " + result.status);
    add(block, "b", "", asset.name + " · " + result.label + (asset.is_demo ? "（演示资产）" : ""));
    add(block, "p", "desc", asset.asset_id + " · " + inventorySummary(asset));
    add(block, "p", "desc", result.reason + "；" + result.priority);
    var activeChecks = (result.checks || []).filter(function (row) { return row.status === result.status; });
    activeChecks.forEach(function (row) { add(block, "p", "meta", "来源范围：" + row.range + " · " + row.pointer); });
    (result.evidence_ids || []).forEach(function (id) {
      var evidence = (report.evidence || []).find(function (row) { return row.citation_id === id; });
      if (!evidence) return;
      var link = add(block, "a", "meta", "范围证据：" + id);
      link.href = evidence.url; link.target = "_blank"; link.rel = "noopener";
    });
  });
  (report.limitations || []).concat(report.warnings || []).forEach(function (text) { add(target, "p", "meta", text); });
  if (report.source) add(target, "p", "meta", "漏洞范围快照获取于 " + dateText(report.source.retrieved_at));
}

function evaluateSavedAssets() {
  try { return api("/api/asset-impact/" + encodeURIComponent(selectedAssetCve())).then(renderAssetImpact); }
  catch (error) { showError(error); return Promise.resolve(); }
}

$("asset-demo").addEventListener("click", function () {
  api("/api/assets/demo").then(function (data) {
    $("asset-json").value = JSON.stringify(data, null, 2);
    $("asset-message").textContent = "已填入 3 条虚构演示资产，尚未保存。选择 CVE-2024-37032 后可预览。";
    $("asset-cve").value = "CVE-2024-37032";
  }).catch(showError);
});
$("asset-file").addEventListener("change", function () {
  var file = this.files[0];
  if (!file) return;
  if (file.size > 1024 * 1024) { showError(new Error("JSON 文件不能超过 1 MB。")); return; }
  file.text().then(function (text) { $("asset-json").value = text.replace(/^\uFEFF/, ""); $("asset-message").textContent = "已读取文件，尚未保存；请先预览核对。"; }).catch(showError);
});
$("asset-preview").addEventListener("click", function () {
  clearError();
  var button = $("asset-preview");
  try {
    var payload = assetPayload();
    payload.cve_id = selectedAssetCve();
    button.disabled = true;
    api("/api/assets/preview", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}).then(renderAssetImpact).catch(showError).then(function () { button.disabled = false; });
  } catch (error) { showError(error); }
});
$("asset-save").addEventListener("click", function () {
  clearError();
  var button = $("asset-save");
  try {
    var payload = assetPayload();
    button.disabled = true;
    api("/api/assets/import", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}).then(function (data) {
      $("asset-message").textContent = "已保存：新增 " + data.created + " 条，更新 " + data.updated + " 条；其他已登记资产保留。";
      clear($("asset-impact"));
      add($("asset-impact"), "p", "empty", "清单已更新，请重新评估已保存清单。");
      return loadAssets();
    }).catch(showError).then(function () { button.disabled = false; });
  } catch (error) { showError(error); }
});
$("asset-evaluate").addEventListener("click", function () { clearError(); evaluateSavedAssets().catch(showError); });
$("asset-cve").addEventListener("change", function () { clear($("asset-impact")); add($("asset-impact"), "p", "empty", "情报已切换，请重新预览或评估。"); });

function fillFocus(items) {
  var select = $("focus");
  var current = select.value;
  clear(select);
  var any = add(select, "option", "", "不限定");
  any.value = "";
  items.forEach(function (item) {
    var option = add(select, "option", "", item.cve_id);
    option.value = item.cve_id;
  });
  select.value = current;
}

function loadAsk() {
  api("/api/items").then(function (data) {
    fillFocus(data.items || []);
  }).catch(showError);
}

$("sample-btn").addEventListener("click", function () {
  var button = $("sample-btn");
  button.disabled = true;
  clearError();
  api("/api/sample", { method: "POST" }).then(function (sample) {
    return api("/api/items").then(function (data) {
      fillFocus(data.items || []);
      $("focus").value = sample.cve_id;
      $("question").value = prompts[0];
      button.textContent = "历史样例已载入";
    });
  }).catch(showError).then(function () { button.disabled = false; });
});

function loadSettings() {
  api("/api/settings").then(function (data) {
    $("base-url").value = data.base_url || "";
    $("model-name").value = data.model || "";
    $("api-key").value = "";
    $("key-hint").textContent = data.key_hint || "";
    setPill(data.has_key);
  }).catch(showError);
}

document.querySelectorAll(".nav button").forEach(function (button) {
  button.addEventListener("click", function () {
    setView(button.getAttribute("data-view"));
  });
});

$("goto-monitor").addEventListener("click", function () { setView("monitor"); });

$("filter").addEventListener("input", function () { loadItems("monitor"); });

$("collect-form").addEventListener("submit", function (event) {
  event.preventDefault();
  var button = $("collect-btn");
  button.disabled = true;
  button.textContent = "正在监测 NVD 与 OSV…";
  clearError();
  api("/api/collect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ keyword: $("keyword").value.trim() || "ollama" })
  }).then(function () {
    loadItems("monitor");
  }).catch(showError).then(function () {
    button.disabled = false;
    button.textContent = "开始监测";
  });
});

$("enrich-btn").addEventListener("click", function () {
  var button = $("enrich-btn");
  button.disabled = true;
  button.textContent = "正在查询公开源…";
  clearError();
  api("/api/enrich", { method: "POST" }).then(function () {
    loadItems("enrich");
    button.textContent = "查询完成";
  }).catch(showError).then(function () {
    button.disabled = false;
    if (button.textContent !== "查询完成") button.textContent = "查询 EPSS、KEV 与论文";
  });
});

var promptBox = $("prompts");
prompts.forEach(function (text) {
  var button = add(promptBox, "button", "", text);
  button.type = "button";
  button.addEventListener("click", function () {
    $("question").value = text;
  });
});

$("ask-form").addEventListener("submit", function (event) {
  event.preventDefault();
  var button = $("ask-btn");
  button.disabled = true;
  clearError();
  api("/api/ask", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      question: $("question").value.trim(),
      cve_id: $("focus").value
    })
  }).then(function (data) {
    var answer = $("answer");
    clear(answer);
    add(answer, "div", "", data.answer);
    $("verdict").textContent = !data.evidence.length ? "证据不足" : (data.verdict.passed ? "引用、编号与分数检查通过" : "检查未通过");
    renderSteps($("ask-steps"), data.steps);
    var evidence = $("evidence");
    clear(evidence);
    if (!data.evidence.length) {
      add(evidence, "p", "empty", "没有召回到情报。");
    }
    (data.evidence_chunks || []).forEach(function (chunk) {
      var block = add(evidence, "div", "evidence-chunk");
      add(block, "div", "title", "[" + chunk.citation_id + "] " + chunk.title);
      add(block, "p", "desc", chunk.text);
      add(block, "div", "meta", "原文定位：" + chunk.locator);
      var kinds = {reviewed_manual_summary: "人工核对摘要", user_declared_inventory: "用户登记资产", automatic_structured_extract: "来源字段提取"};
      add(block, "div", "meta", "获取/登记日期：" + dateText(chunk.retrieved_at) + " · " + (kinds[chunk.text_kind] || "自动提取原文"));
      var link = add(block, "a", "", "打开这段证据的来源");
      link.href = chunk.url;
      link.target = "_blank";
      link.rel = "noopener";
    });
    data.evidence.forEach(function (item, index) {
      var block = add(evidence, "div", "mini");
      var text = add(block, "div");
      add(text, "div", "title", "[" + (index + 1) + "] " + item.cve_id);
      add(text, "div", "desc", (item.description || "").slice(0, 180));
      var link = add(text, "a", "", "查看来源");
      link.href = item.url;
      link.target = "_blank";
      link.rel = "noopener";
      add(block, "div", "score " + scoreClass(item.cvss), scoreText(item.cvss));
    });
  }).catch(showError).then(function () {
    button.disabled = false;
  });
});

$("settings-form").addEventListener("submit", function (event) {
  event.preventDefault();
  clearError();
  api("/api/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      base_url: $("base-url").value.trim(),
      model: $("model-name").value.trim(),
      api_key: $("api-key").value.trim()
    })
  }).then(function (data) {
    $("key-hint").textContent = data.key_hint;
    $("api-key").value = "";
    setPill(data.has_key);
  }).catch(showError);
});

$("test-llm").addEventListener("click", function () {
  $("test-result").textContent = "正在测试…";
  api("/api/settings/test", { method: "POST" }).then(function (data) {
    $("test-result").textContent = data.reply || "连接成功";
  }).catch(function (error) {
    $("test-result").textContent = error.message;
  });
});

setView("overview");
