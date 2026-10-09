var titles = {
  overview: "总览",
  monitor: "情报监测",
  enrich: "情报富化",
  library: "安全资料库",
  assets: "资产影响",
  ask: "情报问答",
  settings: "模型设置"
};

var prompts = [
  "CVE-2024-37032 应该升级到哪个版本？有哪些缓解建议？",
  "CVE-2024-37032 的受影响版本是什么，如何修复？有没有修复记录？",
  "CVE-2025-0312 的风险有多高？影响哪个版本？",
  "ollama 相关漏洞里，哪些写了受影响版本？",
  "当前记录有没有被标成 Exploit 的链接？",
  "比较 CVE-2024-37032 和 CVE-2025-0312 的 CVSS、受影响版本与修复记录"
];
var askSessionId = "";

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
  if (name === "library") loadLibrary();
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
      ((data.sources || []).join("、") || "还没有") + "。安全资料库另收录 " + ((data.library || {}).documents || 0) + " 份资料，可在安全资料库查看与检索。";
    [
      [String(data.items), "知识库情报"],
      [String(data.source_count || 0), "漏洞数据库来源"],
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

function renderGuidance(panel, report) {
  var section = add(panel, "div", "guidance");
  add(section, "h3", "", "关联公告与研究建议");
  if (!report || report.status !== "ok") {
    add(section, "p", "meta", "尚无满足关联规则的版本或建议。可点击下方「补充关联建议」读取已知参考来源。");
    return;
  }
  var labels = {versions: "公告版本字段", remediation: "修复与缓解", conditions: "文章中的条件描述"};
  Object.keys(labels).forEach(function (topic) {
    var rows = (report.facets || {})[topic] || [];
    if (!rows.length) return;
    add(section, "h4", "", labels[topic]);
    rows.forEach(function (row) {
      var block = add(section, "div", "guidance-fact");
      add(block, "span", "tag", row.authority === "vendor_statement" ? "项目方公告声明" : "研究方建议 / 描述");
      add(block, "span", "meta", " · " + row.publisher);
      var value = row.structured_value || {}, text = row.text;
      if (value.vulnerable_version_range) text = value.package.name + " · 受影响版本范围：" + value.vulnerable_version_range;
      if (value.patched_versions) text = value.package.name + " · 公告修复版本范围：" + value.patched_versions;
      if (value.recommended_version_range) text = value.product + " · 研究方建议升级到：" + value.recommended_version_range;
      add(block, "p", "desc", text);
      var detail = add(block, "details", "");
      add(detail, "summary", "meta", "查看原文与引用");
      (row.evidence_ids || []).forEach(function (id) {
        var chunk = (report.evidence || []).find(function (e) { return e.citation_id === id; });
        if (!chunk) return;
        add(detail, "p", "desc", chunk.text);
        var link = add(detail, "a", "meta", id); link.href = chunk.url; link.target = "_blank"; link.rel = "noopener";
        add(detail, "p", "meta", chunk.locator + " · 获取于 " + dateText(chunk.retrieved_at));
      });
    });
  });
  (report.sources || []).filter(function (r) { return r.retained_previous; }).forEach(function (r) {
    add(section, "p", "meta", "来源本次更新失败，沿用获取于 " + dateText(r.retrieved_at) + " 的成功存档：" + r.publisher);
  });
  add(section, "p", "meta", "本项目未测试这些修复或缓解措施；文章描述中的部署条件需结合实际配置核对。");
  (report.limitations || []).forEach(function (text) { add(section, "p", "meta", text); });
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
  renderGuidance(panel, item.related_guidance);
  var guidanceButton = add(panel, "button", "ghost", "补充关联建议");
  guidanceButton.type = "button";
  guidanceButton.addEventListener("click", function () {
    guidanceButton.disabled = true;
    guidanceButton.textContent = "正在读取公告与研究来源…";
    api("/api/guidance/" + encodeURIComponent(item.cve_id) + "/refresh", {method: "POST"}).then(function (data) {
      var previous = panel.querySelector(".guidance");
      renderGuidance(panel, data.guidance);
      if (previous) previous.replaceWith(panel.lastElementChild);
      guidanceButton.textContent = "本次成功 " + data.ok + "/" + data.attempted + " 个关联来源";
    }).catch(showError).then(function () { guidanceButton.disabled = false; });
  });
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

$("new-session").addEventListener("click", function () {
  askSessionId = "";
  $("focus").value = "";
  $("question").value = "";
  ["answer", "evidence", "ask-steps"].forEach(function (id) { clear($(id)); });
  $("verdict").textContent = "";
  $("conversation-context").textContent = "已开始新会话，请先指定漏洞。会话在本机进程内保留，空闲两小时或服务重启后失效。";
  clearError();
});

$("ask-form").addEventListener("submit", function (event) {
  event.preventDefault();
  var button = $("ask-btn");
  button.disabled = true;
  $("new-session").disabled = true;
  clearError();
  var question = $("question").value.trim();
  var explicit = question.match(/CVE-\d{4}-\d{4,7}\b/gi) || [];
  if (explicit.length) $("focus").value = "";
  api("/api/ask", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      question: question,
      cve_id: $("focus").value,
      session_id: askSessionId
    })
  }).then(function (data) {
    var answer = $("answer");
    clear(answer);
    askSessionId = data.session_id;
    $("conversation-context").textContent = "第 " + data.turn + " 轮 · " + ((data.context.cve_ids || []).join("、") || "未限定漏洞") + " · " + data.context.notice;
    (data.history || []).forEach(function (turn) {
      if (turn.turn === data.turn) {
        add(answer, "h3", "", "第 " + turn.turn + " 轮：" + turn.question);
        add(answer, "div", "", data.answer);
      } else {
        var previous = add(answer, "details", "conversation-turn");
        add(previous, "summary", "", "第 " + turn.turn + " 轮：" + turn.question);
        add(previous, "div", "", turn.answer);
        add(previous, "p", "meta", "历史回答；右侧证据对应最新一轮。超过长度的历史回答仅保留前 12000 字符。");
      }
    });
    $("question").value = "";
    var answerMode = data.used_model ? "模型回答" : (data.model_attempted ? "模型回退到证据摘录" : "规则回答");
    $("verdict").textContent = !data.evidence.length ? "证据不足" : answerMode + " · " + (data.verdict.passed ? "引用、编号与分数检查通过" : "检查未通过");
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
    $("new-session").disabled = false;
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

var libraryKinds = {vendor_advisory: "项目安全公告", vendor_guidance: "厂商安全文档", research_article: "安全研究文章", academic_paper: "论文", standard: "标准 / 风险框架", policy: "政策法规"};
var libraryScopes = {team_summary: "队友接口题名/描述，非原始全文", abstract: "仅摘要", article_body: "文章正文", advisory_fields: "公告正文及字段", full_text_html: "HTML 全文文字", full_text_pdf: "PDF 各页文字", policy_articles: "政策条文", catalog_only: "仅目录"};
var libraryTopics = {prompt_injection: "提示注入", jailbreak: "越狱与对抗攻击", model_supply_chain: "模型供应链", agent_security: "智能体安全", ai_infrastructure: "AI 基础设施", ai_governance: "AI 风险治理", content_labeling: "生成内容标识"};
var librarySelectedDocs = [];

function libraryLink(parent, url, text) {
  var link = add(parent, "a", "", text);
  link.href = url; link.target = "_blank"; link.rel = "noopener";
  return link;
}

function renderLibraryEvidence(data) {
  var target = $("library-evidence"); clear(target);
  add(target, "p", "hint", data.notice || "引用对应已存档的提取内容；字符定位不是网页行号。");
  var rows = data.evidence || [];
  if (!rows.length) add(target, "p", "empty", "没有匹配的原文。可切换资料类型或检索词。");
  rows.forEach(function (row) {
    var block = add(target, "div", "evidence-chunk");
    add(block, "div", "title", row.title);
    add(block, "p", "meta", "[" + row.citation_id + "] · " + libraryScopes[row.content_scope]);
    add(block, "p", "desc", row.text);
    add(block, "p", "meta", "原文定位：" + row.locator);
    add(block, "p", "meta", "获取时间：" + dateText(row.retrieved_at));
    (row.associations || []).forEach(function (relation) {
      add(block, "p", "meta", relation.entity_id + " · " + relation.reason);
    });
    libraryLink(block, row.url + (row.locator.indexOf("PDF page ") === 0 ? "#page=" + row.locator.match(/^PDF page (\d+)/)[1] : ""), "打开原始来源");
  });
}

function renderLibraryRelations(data) {
  var target = $("library-relations"); clear(target);
  var facts = data.facts || [];
  if (facts.length) add(target, "h3", "", "来源事实与限定条件");
  var roles = {mechanism: "风险机制", condition: "场景条件", impact: "可能影响", mitigation: "潜在防护", limitation: "防护局限", assessment: "评估建议", provenance: "引用关系"};
  facts.forEach(function (fact) {
    var block = add(target, "details", "relation-fact");
    add(block, "summary", "", (roles[fact.facet] || fact.facet) + " · " + fact.label + " · " + fact.publisher);
    add(block, "p", "", fact.text);
    add(block, "p", "hint", "限定：" + fact.qualifier);
    add(block, "p", "meta", "资料版本：" + fact.version + "；引用：" + fact.evidence_ids.join("、"));
  });
  (data.unavailable_facts || []).forEach(function (item) { add(target, "p", "hint", item.fact_id + "：" + item.reason); });
  var supplements = data.reviewed_quotes || {};
  if ((supplements.facts || []).length) {
    add(target, "h3", "", "已复核的补充原文（未用作综合前提）");
    supplements.facts.forEach(function (fact) {
      var block = add(target, "details", "relation-fact");
      add(block, "summary", "", (roles[fact.facet] || fact.facet) + " · " + fact.publisher);
      add(block, "p", "", fact.text);
      renderCandidateRelation(block, fact);
      add(block, "p", "hint", fact.qualifier + "；审核：" + fact.review.reviewer + " · " + fact.review.review_kind);
      add(block, "p", "meta", "引用：" + fact.evidence_ids.join("、"));
    });
  }
  if (!facts.length && !(supplements.facts || []).length) add(target, "p", "empty", "暂无来源有效且已通过复核的关系。");
}

var candidateLabels = {mechanism: "风险机制", condition: "场景条件", impact: "可能影响", mitigation: "潜在防护", limitation: "防护局限", assessment: "评估建议"};
function renderCandidateRelation(block, item) {
  if (item.topic !== "article_relations") return;
  var relation = item.relation;
  if (relation) {
    add(block, "p", "title", "主语：" + relation.subject);
    add(block, "p", "", "关系：" + relation.predicate + "；宾语：" + relation.object);
    add(block, "p", "hint", "提取条件：" + (relation.conditions.length ? relation.conditions.join("；") : "未提取到明确条件，需核对整句，不能理解为无条件"));
  } else add(block, "p", "hint", "句子候选：尚未提取结构化关系，需结合原文审核。");
  add(block, "p", "hint", item.scope_notice + "；保留整句中的范围、情态和否定词，语义完整性需复核。");
}
function renderCandidates(data) {
  var target = $("candidate-list"); clear(target);
  $("candidate-status").textContent = (data.note || data.notice || "") + " 当前显示 " + data.items.length + " 项。";
  var states = {pending: "待审核", approved: "已通过", rejected: "已拒绝", revoked: "已撤销", stale: "来源变化或不可用，已失效"};
  data.items.forEach(function (item) {
    var block = add(target, "details", "relation-fact");
    var reviewedFacet = item.reviews.length ? item.reviews[item.reviews.length - 1].facet : item.facet;
    add(block, "summary", "", states[item.effective_state] + " · " + candidateLabels[reviewedFacet] + " · " + item.publisher);
    add(block, "p", "", item.quote);
    renderCandidateRelation(block, item);
    add(block, "p", "meta", item.citation_id + " · " + item.locator);
    add(block, "p", "hint", "来源版本：" + (item.version || "页面未注明版本；按存档核对") + "；获取于 " + dateText(item.retrieved_at) + (item.retained_previous ? "；沿用旧存档" : ""));
    libraryLink(block, item.url + (item.locator.indexOf("PDF page ") === 0 ? "#page=" + item.locator.match(/^PDF page (\d+)/)[1] : ""), "打开原始来源");
    var original = add(block, "button", "ghost", "查看存档原文"); original.type = "button";
    original.addEventListener("click", function () { api("/api/library/" + item.document_id).then(renderLibraryEvidence).catch(showError); });
    (item.reviews || []).forEach(function (event) { add(block, "p", "hint", "审核记录：" + states[event.decision] + " · " + candidateLabels[event.facet] + " · " + event.reviewer + " · " + event.review_kind + " · " + dateText(event.reviewed_at) + "；" + event.note); });
    if (item.state !== "pending" && item.state !== "approved") return;
    var form = add(block, "form", "");
    var facetLabel = add(form, "label", "", "核对后分类");
    var facet = add(facetLabel, "select", "");
    Object.keys(candidateLabels).forEach(function (key) { var opt = add(facet, "option", "", candidateLabels[key]); opt.value = key; });
    facet.value = item.reviews.length ? item.reviews[item.reviews.length - 1].facet : item.facet;
    var reviewerLabel = add(form, "label", "", "审核者");
    var reviewer = add(reviewerLabel, "input", ""); reviewer.required = true; reviewer.maxLength = 80;
    var kindLabel = add(form, "label", "", "审核类型");
    var kind = add(kindLabel, "select", "");
    [{value: "user_source_review", label: "人工来源核对（不计独立验收）"}, {value: "developer_source_review", label: "开发来源核对（不计独立验收）"}].forEach(function (item) { var opt = add(kind, "option", "", item.label); opt.value = item.value; });
    var noteLabel = add(form, "label", "", "核对说明（至少 10 字符）");
    var note = add(noteLabel, "textarea", ""); note.required = true; note.minLength = 10; note.maxLength = 1000; note.rows = 2;
    var actions = add(form, "div", "toolbar");
    var decisions = item.state === "approved" ? ["revoked"] : ["approved", "rejected"];
    decisions.forEach(function (decision) {
      var button = add(actions, "button", "ghost", {approved: item.topic === "article_relations" ? "通过原文关系与条件核对" : "通过主题关联与分类", rejected: "拒绝候选", revoked: "撤销通过"}[decision]);
      button.type = "button"; button.disabled = decision === "approved" && !item.source_binding_valid;
      button.addEventListener("click", function () {
        if (!form.reportValidity()) return;
        button.disabled = true;
        api("/api/library/relations/candidates/" + item.id + "/review", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({decision: decision, facet: facet.value, reviewer: reviewer.value.trim(), note: note.value.trim(), review_kind: kind.value})}).then(function () {
          clear($("library-relations")); clear($("library-evidence")); $("library-answer").textContent = "审核状态已变更，请重新提问。";
          return loadCandidates();
        }).catch(showError).then(function () { button.disabled = false; });
      });
    });
    form.addEventListener("submit", function (event) { event.preventDefault(); });
  });
}
function loadCandidates() {
  var topic = $("candidate-topic").value;
  return api("/api/library/relations/candidates?topic=" + encodeURIComponent(topic)).then(function (data) { if (topic === $("candidate-topic").value) renderCandidates(data); }).catch(showError);
}
$("candidate-refresh").addEventListener("click", loadCandidates);
$("candidate-graph").addEventListener("click", function () {
  var topic = $("candidate-topic").value;
  api("/api/library/relations/graph?topic=" + encodeURIComponent(topic)).then(function (data) {
    if (topic === $("candidate-topic").value) renderLibraryRelations(data);
  }).catch(showError);
});
$("candidate-topic").addEventListener("change", function () { clear($("candidate-list")); loadCandidates(); });
$("candidate-generate").addEventListener("click", function () {
  var button = $("candidate-generate"), topic = $("candidate-topic").value;
  var ids = topic === "article_relations" ? librarySelectedDocs.slice() : [];
  if (topic === "article_relations" && !ids.length) { $("candidate-status").textContent = "请先在下方资料列表勾选 1 至 4 份资料，再提取文章关系。"; return; }
  button.disabled = true;
  $("candidate-status").textContent = "正在提取候选，所有新候选均需审核…";
  api("/api/library/relations/candidates", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({topic: topic, document_ids: ids})}).then(function (data) { if (topic === $("candidate-topic").value) renderCandidates(data); }).catch(function (error) { if (topic === $("candidate-topic").value) $("candidate-status").textContent = "提取失败，请检查所选资料与来源状态。"; showError(error); }).then(function () { button.disabled = false; });
});

function loadLibrary() {
  return api("/api/library?document_type=" + encodeURIComponent($("library-type").value)).then(function (data) {
    var counts = data.overview.types;
    $("library-summary").textContent = "本机已收录 " + data.overview.documents + " 份资料、" + data.overview.chunks + " 段存档内容；标准 / 风险框架 " + counts.standard + "、政策法规 " + counts.policy + "。";
    var sources = $("library-sources"); clear(sources);
    (data.overview.sources || []).forEach(function (source) {
      add(sources, "p", "meta", source.name + "：" + (source.status === "ok" ? "发现 " + source.discovered + " 份候选" : source.status === "partial" ? "部分资料同步失败" : "同步失败") + " · " + dateText(source.checked_at) + (source.error ? " · " + source.error : ""));
      if (typeof source.remaining === "number" && source.remaining) add(sources, "p", "hint", "本轮只处理最近更新的 " + source.discovered + " 份，还有 " + source.remaining + " 份不在本轮窗口内。");
    });
    (data.overview.failed_documents || []).forEach(function (row) {
      var block = add(sources, "div", "meta");
      add(block, "p", "", "资料抓取失败" + (row.retained_previous ? "，保留上次成功证据" : "，尚未入库") + "：" + row.error);
      libraryLink(block, row.url, "查看失败来源");
    });
    var target = $("library-list"); clear(target);
    if (!data.items.length) add(target, "p", "empty", "此类型尚未收录资料。");
    data.items.forEach(function (doc) {
      var block = add(target, "div", "evidence-chunk");
      var button = add(block, "button", "text-btn", doc.title);
      button.type = "button";
      button.addEventListener("click", function () {
        api("/api/library/" + encodeURIComponent(doc.document_id)).then(renderLibraryEvidence).catch(showError);
      });
      add(block, "p", "meta", libraryKinds[doc.document_type] + " · " + doc.publisher + " · " + dateText(doc.published_at));
      var discoveryLabels = {team_api: "队友接口存档", explicit_source_text: "显式获取来源原文", historical_seed: "历史起始资料", explicit_full_text: "显式获取全文", fixed_reference_monitor: "固定官方原文监测", subscription: "订阅发现"};
      add(block, "p", "meta", libraryScopes[doc.content_scope] + " · " + doc.chunk_count + " 段 · " + (discoveryLabels[doc.discovery] || doc.discovery) + (doc.retained_previous ? " · 刷新失败，保留旧快照" : ""));
      if (doc.version) add(block, "p", "meta", "版本：" + doc.version);
      if (doc.team_document_id) add(block, "p", "meta", "队友记录：" + doc.team_document_id + " · 更新于 " + dateText(doc.team_content_updated_at));
      if (doc.effective_at) add(block, "p", "meta", "原文实施 / 施行日期：" + doc.effective_at);
      if (doc.extraction_notice) add(block, "p", "hint", doc.extraction_notice);
      var selection = add(block, "label", "library-selection");
      var check = add(selection, "input", ""); check.type = "checkbox"; check.checked = librarySelectedDocs.indexOf(doc.document_id) >= 0;
      selection.appendChild(document.createTextNode(" 用于资料问答或文章关系提取"));
      check.addEventListener("change", function () {
        if (check.checked && librarySelectedDocs.length >= 4) { check.checked = false; showError(new Error("最多选择 4 份资料")); return; }
        librarySelectedDocs = librarySelectedDocs.filter(function (id) { return id !== doc.document_id; });
        if (check.checked) librarySelectedDocs.push(doc.document_id);
      });
      if ((doc.content_scope === "abstract" || doc.content_scope === "team_summary") && doc.document_type === "academic_paper" && /^https:\/\/arxiv\.org\/abs\//.test(doc.url)) {
        var fullLabel = data.items.some(function (r) { return r.parent_document_id === doc.document_id; }) ? "刷新论文全文" : "获取论文全文";
        var fullButton = add(block, "button", "ghost", fullLabel);
        fullButton.type = "button";
        fullButton.addEventListener("click", function () {
          fullButton.disabled = true; fullButton.textContent = "正在获取官方全文…";
          api("/api/library/" + doc.document_id + "/full-text", {method: "POST"}).then(function (result) {
            if (result.status !== "ok") throw new Error("全文未获取成功，保留摘要：" + (result.error || "来源暂时不可用"));
            librarySelectedDocs = librarySelectedDocs.filter(function (id) { return id !== doc.document_id; });
            $("library-answer").textContent = "全文已更新，请重新选择资料并提问。";
            clear($("library-relations")); clear($("library-evidence"));
            return loadLibrary();
          }).catch(showError).then(function () { fullButton.disabled = false; fullButton.textContent = fullLabel; });
        });
      }
      if (doc.content_scope === "team_summary" && ["research_article", "vendor_advisory"].indexOf(doc.document_type) >= 0) {
        var sourceButton = add(block, "button", "ghost", "获取来源原文"); sourceButton.type = "button";
        sourceButton.addEventListener("click", function () {
          sourceButton.disabled = true; sourceButton.textContent = "正在获取来源原文…";
          api("/api/library/" + doc.document_id + "/full-text", {method: "POST"}).then(function (result) {
            if (result.status !== "ok") throw new Error("来源原文未获取成功，描述存档仍可使用：" + (result.error || "来源暂时不可用"));
            librarySelectedDocs = [result.document_id]; clear($("library-evidence")); clear($("library-relations"));
            $("library-answer").textContent = "来源原文已入库并选中，可以按证据提问。";
            return loadLibrary();
          }).catch(showError).then(function () { sourceButton.disabled = false; sourceButton.textContent = "获取来源原文"; });
        });
      }
      add(block, "p", "meta", "主题：" + (doc.topic_tags || []).map(function (tag) { return libraryTopics[tag] || tag; }).join("、"));
      libraryLink(block, doc.url, "打开来源");
    });
  }).catch(showError);
}

$("library-type").addEventListener("change", function () { librarySelectedDocs = []; loadLibrary(); clear($("library-evidence")); clear($("library-relations")); $("library-answer").textContent = "资料类型已切换，请重新选择资料并提问。"; });
$("library-mode").addEventListener("change", function () { clear($("library-relations")); clear($("library-evidence")); $("library-answer").textContent = "回答方式已切换，请重新提问。"; });
$("library-example").addEventListener("click", function () { $("library-mode").value = "excerpt"; clear($("library-relations")); clear($("library-evidence")); $("library-question").value = "管理暂行办法对训练数据有什么规定？适用范围是什么？"; $("library-answer").textContent = "已填入政策示例，请选择对应政策并提问。"; });
$("library-relations-example").addEventListener("click", function () {
  $("library-mode").value = "relations"; $("library-type").value = ""; librarySelectedDocs = [];
  $("library-question").value = "比较论文和 NIST 对间接提示注入的机制解释、防护建议及局限。";
  clear($("library-relations")); clear($("library-evidence")); $("library-answer").textContent = "已填入关系示例，将使用已核对的论文全文与 NIST 框架。"; loadLibrary();
});
$("library-supply-example").addEventListener("click", function () {
  $("library-mode").value = "relations"; $("library-type").value = ""; librarySelectedDocs = [];
  $("library-question").value = "比较 HF 和 NIST 对模型供应链的加载风险、防护建议与扫描局限。";
  clear($("library-relations")); clear($("library-evidence")); $("library-answer").textContent = "已填入供应链示例，将使用 HF 文档存档与 NIST 框架。"; loadLibrary();
});
$("library-ask-form").addEventListener("submit", function (event) {
  event.preventDefault(); clearError();
  var button = $("library-ask"); button.disabled = true; button.textContent = "正在检索原文…";
  $("library-answer").textContent = "正在按资料证据处理…"; clear($("library-evidence")); clear($("library-relations"));
  var requestMode = $("library-mode").value;
  var requestBody = JSON.stringify({question: $("library-question").value.trim(), document_ids: librarySelectedDocs, document_type: $("library-type").value});
  api(requestMode === "relations" ? "/api/library/analyze" : "/api/library/ask", {method: "POST", headers: {"Content-Type": "application/json"}, body: requestBody}).then(function (result) {
    if (requestMode !== $("library-mode").value || requestBody !== JSON.stringify({question: $("library-question").value.trim(), document_ids: librarySelectedDocs, document_type: $("library-type").value})) { $("library-answer").textContent = "问题或选择已变化，请重新提问。"; return; }
    $("library-answer").textContent = result.answer;
    renderLibraryRelations(result);
    var rows = result.evidence || [];
    ((result.reviewed_quotes || {}).evidence || []).forEach(function (row) { if (!rows.some(function (r) { return r.citation_id === row.citation_id; })) rows.push(row); });
    renderLibraryEvidence({evidence: rows, notice: requestMode === "relations" ? "限定综合与来源事实分开展示；原文可在此核对。" : result.used_model ? "模型挑选的原文已核对；不构成自由推理结论。" : "依据检索原文摘录。"});
  }).catch(showError).then(function () { button.disabled = false; button.textContent = "按证据回答"; });
});
$("library-search-form").addEventListener("submit", function (event) {
  event.preventDefault(); clearError();
  api("/api/library/search?q=" + encodeURIComponent($("library-query").value.trim()) + "&document_type=" + encodeURIComponent($("library-type").value)).then(renderLibraryEvidence).catch(showError);
});
$("library-sync").addEventListener("click", function () {
  var button = $("library-sync"); button.disabled = true; button.textContent = "正在同步公开资料…"; clearError();
  api("/api/library/sync", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({per_source: 3, include_seeds: true})}).then(function (data) {
    button.textContent = "本轮入库成功 " + data.ok + "/" + data.attempted + " 份";
    clear($("library-evidence"));
    clear($("library-relations"));
    $("library-answer").textContent = "资料已更新，请重新提问。";
    add($("library-evidence"), "p", "hint", "资料已更新，请重新选择资料或检索。");
    return loadLibrary();
  }).catch(showError).then(function () { button.disabled = false; });
});

$("library-team-sync").addEventListener("click", function () {
  var button = $("library-team-sync"); button.disabled = true; button.textContent = "正在同步团队资料…"; clearError();
  api("/api/library/team-sync", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({max_documents: 30})}).then(function (data) {
    button.textContent = "本轮团队资料入库 " + data.ok + "/" + data.attempted + " 份";
    librarySelectedDocs = []; clear($("library-evidence")); clear($("library-relations"));
    $("library-answer").textContent = data.status === "error" ? "队友资料服务未连通，已有资料可继续使用。" : "团队资料已同步，请重新选择资料并提问。";
    return loadLibrary();
  }).catch(showError).then(function () { button.disabled = false; });
});

setView("overview");
