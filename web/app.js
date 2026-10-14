var titles = {
  overview: "总览",
  monitor: "情报监测",
  enrich: "情报富集",
  risks: "资产风险",
  library: "资料库",
  assets: "情报富集",
  ask: "证据问答",
  settings: "模型设置"
};
var eyebrows = {
  overview: "工作台",
  monitor: "CVE + 资料情报流",
  enrich: "EPSS / KEV / 论文 / 影响资产",
  risks: "自动关联 · 证据研判 · 处置跟踪",
  library: "可检索原文与片段",
  assets: "EPSS / KEV / 论文 / 影响资产",
  ask: "先证据后回答",
  settings: "模型接口"
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
var monitorRefreshing = false;
var monitorElapsedTimer = null;
var monitorPollTimer = null;
var monitorRefreshStartedAt = 0;
var lastMonitorStatus = null;
var lastMonitorToastPhase = "";
var selectedMonitorId = null;
var offlineDemo = false;
var offlineModeKnown = false;

function $(id) {
  return document.getElementById(id);
}

function on(id, event, handler) {
  var el = $(id);
  if (!el) {
    console.warn("missing control", id);
    return;
  }
  el.addEventListener(event, handler);
}

function api(path, options) {
  return fetch(path, options).then(function (response) {
    var ctype = (response.headers.get("content-type") || "").toLowerCase();
    var parse = ctype.indexOf("application/json") >= 0
      ? response.json()
      : response.text().then(function (text) {
        try { return JSON.parse(text); }
        catch (e) { return { detail: text ? text.slice(0, 200) : "空响应" }; }
      });
    return parse.then(function (data) {
      if (!response.ok) {
        var detail = data && data.detail ? data.detail : ("请求失败 HTTP " + response.status);
        if (Array.isArray(detail)) detail = "字段校验未通过：" + detail.slice(0, 3).map(function (row) { return (row.loc || []).slice(1).join(".") + "：" + row.msg; }).join("；");
        if (typeof detail === "string" && /^Internal Server Error$/i.test(detail.trim())) {
          detail = "服务端错误（HTTP " + response.status + "）。打开情报详情时若反复失败，请安装 lxml_html_clean 并重启服务。";
        }
        throw new Error(typeof detail === "string" ? detail : "请求失败");
      }
      return data;
    });
  }).catch(function (error) {
    if (error && error.message && error.name !== "Error") {
      throw new Error("网络或服务不可达：" + error.message);
    }
    throw error;
  });
}

var LIST_PAGE_SIZE = 20;
var OVERVIEW_PAGE_SIZE = 8;
var listPages = { monitor: 1, enrich: 1, library: 1, recent: 1, steps: 1 };

function pageSlice(items, key, pageSize) {
  var total = (items || []).length;
  var size = pageSize || LIST_PAGE_SIZE;
  var pages = Math.max(1, Math.ceil(total / size) || 1);
  var page = listPages[key] || 1;
  if (page > pages) page = pages;
  if (page < 1) page = 1;
  listPages[key] = page;
  var start = (page - 1) * size;
  return {
    page: page,
    pages: pages,
    total: total,
    size: size,
    items: (items || []).slice(start, start + size),
  };
}

function renderPager(parent, key, meta, onChange) {
  if (!parent || !meta || meta.total <= meta.size) return;
  var bar = add(parent, "div", "pager");
  bar.setAttribute("role", "navigation");
  bar.setAttribute("aria-label", "分页");
  var info = add(bar, "span", "pager-info", "第 " + meta.page + "/" + meta.pages + " 页 · 共 " + meta.total + " 条");
  var prev = add(bar, "button", "ghost pager-btn", "上一页");
  prev.type = "button";
  prev.disabled = meta.page <= 1;
  var next = add(bar, "button", "ghost pager-btn", "下一页");
  next.type = "button";
  next.disabled = meta.page >= meta.pages;
  prev.addEventListener("click", function () {
    if (listPages[key] > 1) {
      listPages[key] -= 1;
      onChange();
    }
  });
  next.addEventListener("click", function () {
    if (listPages[key] < meta.pages) {
      listPages[key] += 1;
      onChange();
    }
  });
  return info;
}

function showError(error) {
  var banner = $("banner");
  banner.hidden = false;
  banner.textContent = error.message || "请求失败";
  showToast(error.message || "请求失败", "error");
}

function clearError() {
  $("banner").hidden = true;
}

var toastTimer = null;
function showToast(text, kind) {
  var toast = $("toast");
  if (!toast) {
    console.warn("toast missing:", text);
    return;
  }
  toast.hidden = false;
  toast.className = "toast" + (kind === "error" ? " is-error" : kind === "busy" ? " is-busy" : " is-ok");
  toast.textContent = text || (kind === "busy" ? "处理中…" : "完成");
  if (toastTimer) clearTimeout(toastTimer);
  if (kind !== "busy") {
    toastTimer = setTimeout(function () { toast.hidden = true; }, 7000);
  }
}

function setBusyButton(button, busy, busyLabel, idleLabel) {
  if (!button) return;
  button.disabled = !!busy;
  if (busy) {
    button.classList.add("btn-busy");
    button.setAttribute("aria-busy", "true");
    if (busyLabel) button.textContent = busyLabel;
  } else {
    button.classList.remove("btn-busy");
    button.removeAttribute("aria-busy");
    if (idleLabel) button.textContent = idleLabel;
  }
}

var INGEST_PATH_LABELS = {
  "资料库": 1, "资料存档": 1, "资料库沉淀": 1, "资料沉淀": 1, "本地资料库沉淀": 1,
  "LIBRARY": 1, "AGGREGATE": 1, "TEAM": 1, "INTELLIGENCE": 1,
  "多源情报": 1, "多源情报资料": 1, "聚合库": 1
};

/** Origin family = where collected from (not ingest path, not content-only). */
function sourceFamily(raw) {
  var s = String(raw || "").toUpperCase();
  if (!s) return "other";
  if (INGEST_PATH_LABELS[s] || s.indexOf("资料库") >= 0 || s.indexOf("沉淀") >= 0
      || s.indexOf("LIBRARY") >= 0 || s.indexOf("AGGREGATE") >= 0) return "other";
  if (s === "NVD" || s.indexOf("NVD") === 0) return "nvd";
  if (s === "OSV" || s.indexOf("OSV") === 0) return "osv";
  if (s.indexOf("CISA") >= 0 || s.indexOf("KEV") >= 0) return "kev";
  if (s.indexOf("GITHUB") >= 0 || s.indexOf("GHSA") >= 0) return "github";
  if (s.indexOf("VLLM") >= 0 || s.indexOf("OLLAMA") >= 0 || s.indexOf("LANGCHAIN") >= 0
      || s.indexOf("VENDOR") >= 0 || s.indexOf("厂商") >= 0) return "vendor";
  if (s.indexOf("ARXIV") >= 0 || s.indexOf("论文") >= 0 || s.indexOf("学术") >= 0) return "paper";
  if (s.indexOf("TRAIL") >= 0 || s.indexOf("BLOG") >= 0 || s.indexOf("博客") >= 0) return "blog";
  if (s.indexOf("HF_") >= 0 || s.indexOf("HUGGING") >= 0 || s.indexOf("COMMUNITY") >= 0
      || s.indexOf("社区") >= 0) return "community";
  if (s.indexOf("NIST") >= 0 || s.indexOf("FEDERAL") >= 0 || s.indexOf("STANDARD") >= 0
      || s.indexOf("POLICY") >= 0 || s.indexOf("标准") >= 0 || s.indexOf("政策") >= 0) return "standard";
  return "other";
}

function sourceLabel(raw) {
  var s = String(raw || "").trim();
  if (!s || INGEST_PATH_LABELS[s] || INGEST_PATH_LABELS[s.toUpperCase()]) return "来源未写明";
  var specific = {
    NVD: "NVD", OSV: "OSV",
    "GITHUB ADVISORY": "GitHub Advisory", GITHUB_ADVISORY: "GitHub Advisory", GHSA: "GitHub Advisory",
    "CISA KEV": "CISA KEV", CISA_KEV: "CISA KEV",
    ARXIV: "arXiv", ARXIV_AI_SECURITY: "arXiv", "ARXIV FULL TEXT": "arXiv",
    "TRAIL OF BITS": "Trail of Bits", TRAIL_OF_BITS_BLOG: "Trail of Bits", TRAIL_OF_BITS: "Trail of Bits",
    "HUGGING FACE": "Hugging Face", HF_SECURITY_COMMUNITY: "Hugging Face",
    VLLM: "vLLM", VLLM_VENDOR: "vLLM", OLLAMA: "Ollama", OLLAMA_VENDOR: "Ollama",
    LANGCHAIN: "LangChain", LANGCHAIN_VENDOR: "LangChain",
    NIST: "NIST", NIST_CSRC_AI_STANDARDS: "NIST",
    "FEDERAL REGISTER": "Federal Register", FEDERAL_REGISTER_AI_POLICY: "Federal Register"
  };
  var key = s.toUpperCase().replace(/-/g, "_");
  if (specific[key]) return specific[key];
  if (specific[s.toUpperCase()]) return specific[s.toUpperCase()];
  // Keep human publisher strings (arXiv, Trail of Bits, …)
  if (s !== s.toUpperCase() || s.indexOf(" ") >= 0) return s;
  var fam = sourceFamily(raw);
  var map = {
    nvd: "NVD", osv: "OSV", github: "GitHub Advisory", kev: "CISA KEV",
    vendor: "厂商公告源", paper: "论文", blog: "博客", community: "社区", standard: "标准/政策"
  };
  return map[fam] || s;
}

/** Content category = what kind of intel (orthogonal to origin). */
function contentCategory(item) {
  if (!item) return "other";
  if (item.kind !== "document") return "cve";
  var cat = String(item.category || item.category_label || item.content_type || "").toLowerCase();
  if (cat.indexOf("vendor") >= 0 || cat.indexOf("厂商") >= 0 || cat.indexOf("advisory") >= 0 || cat.indexOf("guidance") >= 0) return "vendor";
  if (cat.indexOf("paper") >= 0 || cat.indexOf("academic") >= 0 || cat.indexOf("学术") >= 0 || cat.indexOf("论文") >= 0) return "paper";
  if (cat.indexOf("community") >= 0 || cat.indexOf("blog") >= 0 || cat.indexOf("research") >= 0
      || cat.indexOf("社区") >= 0 || cat.indexOf("博客") >= 0 || cat.indexOf("研究") >= 0) return "community";
  if (cat.indexOf("standard") >= 0 || cat.indexOf("policy") >= 0 || cat.indexOf("标准") >= 0
      || cat.indexOf("政策") >= 0 || cat.indexOf("regulation") >= 0) return "standard";
  return "other";
}

function itemSourceLabels(item) {
  var raws = (item && item.sources) || [];
  if (!raws.length && item && item.source) raws = [item.source];
  // origin/library/team_documents = ingest path only — never invent a 来源 chip from them.
  var labels = [];
  var seen = {};
  raws.forEach(function (r) {
    var label = sourceLabel(r);
    if (label === "来源未写明") return;
    if (!seen[label]) { seen[label] = true; labels.push(label); }
  });
  // Documents with empty collector id: fall back to content-class origin, not ingest path.
  if (!labels.length && item && item.kind === "document") {
    var cat = contentCategory(item);
    var byCat = {vendor: "厂商公告源", paper: "论文", community: "社区", standard: "标准/政策"};
    if (byCat[cat]) labels.push(byCat[cat]);
  }
  return labels.length ? labels : ["来源未写明"];
}

function itemMatchesCategoryFilter(item, filter) {
  if (!filter || filter === "all") return true;
  var cat = contentCategory(item);
  if (filter === "vendor" || filter === "paper" || filter === "community" || filter === "standard") {
    return cat === filter;
  }
  return true;
}

function itemMatchesSourceFilter(item, filter) {
  if (!filter || filter === "all") return true;
  // Legacy ingest-path chips removed from UI; do not match by origin=library/team.
  if (filter === "library" || filter === "aggregate" || filter === "team") return false;
  var raws = (item.sources || []).concat(item.source ? [item.source] : []);
  if (raws.some(function (r) { return sourceFamily(r) === filter; })) return true;
  // Document chips (厂商/社区/论文/博客/标准) also accept content category when collector id is thin.
  if (item.kind === "document") {
    var cat = contentCategory(item);
    if (filter === "vendor" && cat === "vendor") return true;
    if (filter === "paper" && cat === "paper") return true;
    if (filter === "standard" && cat === "standard") return true;
    if (filter === "community" && cat === "community") {
      // community chip excludes pure blog labels when a blog-specific chip exists
      var blob = ((item.source || "") + " " + (item.sources || []).join(" ")).toLowerCase();
      if (blob.indexOf("blog") >= 0 || blob.indexOf("博客") >= 0 || blob.indexOf("trail") >= 0) return false;
      return true;
    }
    if (filter === "blog") {
      var text = ((item.source || "") + " " + (item.sources || []).join(" ") + " " + (item.category || "")).toLowerCase();
      return text.indexOf("blog") >= 0 || text.indexOf("博客") >= 0 || text.indexOf("trail") >= 0
        || text.indexOf("research_article") >= 0 || text.indexOf("security_blog") >= 0;
    }
  }
  return false;
}

function hideToast() {
  var toast = $("toast");
  if (toast) toast.hidden = true;
  if (toastTimer) clearTimeout(toastTimer);
}

function scoreClass(score) {
  if (score == null) return "";
  if (score >= 7) return "high";
  if (score >= 4) return "mid";
  return "low";
}

function scoreText(score) {
  return score == null ? "暂无评分" : String(score);
}

function missingText(value, fallback) {
  if (value == null || value === "") return fallback || "未写明";
  return value;
}

function isDemoItem(item) {
  var cve = item.cve_id || "";
  var title = item.title || "";
  var desc = item.description || "";
  var blob = title + " " + desc;
  var sample = item.sample_mode || ((item.raw_data || {}).sample_mode);
  return !!sample || /^CVE-2099-/.test(cve) || title.indexOf("【演示】") === 0
    || /demo_fixture|Demo offline|Synthetic |【演示】|合成/.test(blob);
}

function dateText(value) {
  if (!value) return "未知";
  var text = String(value);
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) return text;
  return formatStamp(text);
}

function epssText(epss) {
  if (!epss) return "尚未查询";
  if (epss.status === "ok") return String(epss.score) + publicFeedAttemptSuffix(epss);
  if (epss.status === "empty") return "公开源未收录" + publicFeedAttemptSuffix(epss);
  if (epss.status === "error") return "查询失败";
  return "尚未查询";
}

function kevText(kev) {
  if (!kev) return "尚未查询";
  if (kev.status === "listed") return "已列入" + (kev.date_added ? "，" + kev.date_added : "") + publicFeedAttemptSuffix(kev);
  if (kev.status === "not_listed") return "未列入" + publicFeedAttemptSuffix(kev);
  if (kev.status === "error") return "查询失败";
  return "尚未查询";
}

function publicFeedAttemptSuffix(value) {
  if (value.retained_previous && value.latest_attempt && value.latest_attempt.status === "error") {
    return "（本次查询失败，保留上次成功结果" + (value.last_success_at ? "：" + dateText(value.last_success_at) : "") + "）";
  }
  return "";
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
  var isDoc = item.kind === "document";
  var row = add(parent, "button", "row" + (isDoc ? " is-doc" : ""));
  row.type = "button";
  var itemKey = String(item.cve_id || item.id || item.url || "");
  if (itemKey) row.setAttribute("data-item-id", itemKey);
  if (selectedMonitorId && itemKey && selectedMonitorId === itemKey) row.className += " is-selected";
  if (isDemoItem(item) || item.demo) row.className += " is-demo";
  row.addEventListener("click", function () { onPick(item); });
  var id = add(row, "div");
  var primary = isDoc ? (item.category_label || "资料") : (item.cve_id || item.id || "");
  var titleLine = add(id, "div", "title", primary);
  if (isDemoItem(item) || item.demo) {
    var badge = document.createElement("span");
    badge.className = "demo-badge";
    badge.textContent = "演示";
    titleLine.appendChild(document.createTextNode(" "));
    titleLine.appendChild(badge);
  }
  if (isDoc) {
    var kindBadge = document.createElement("span");
    kindBadge.className = "kind-badge";
    kindBadge.textContent = "非CVE";
    titleLine.appendChild(document.createTextNode(" "));
    titleLine.appendChild(kindBadge);
  }
  // Publish date stays in the meta line only — not a second global "时效" badge.
  var labels = itemSourceLabels(item);
  var srcWrap = add(id, "div", "src-row");
  labels.slice(0, 4).forEach(function (label) {
    var fam = "other";
    if (label === "NVD") fam = "nvd";
    else if (label === "OSV") fam = "osv";
    else if (label.indexOf("GitHub") === 0) fam = "gh";
    else if (label.indexOf("KEV") >= 0) fam = "kev";
    else if (label.indexOf("厂商") >= 0) fam = "gh";
    else if (label.indexOf("论文") >= 0 || label.indexOf("arXiv") >= 0) fam = "paper";
    else if (label.indexOf("博客") >= 0 || label.indexOf("Trail") >= 0) fam = "comm";
    else if (label.indexOf("社区") >= 0 || label.indexOf("Hugging") >= 0) fam = "comm";
    else if (label.indexOf("标准") >= 0 || label.indexOf("政策") >= 0 || label.indexOf("NIST") >= 0) fam = "lib";
    add(srcWrap, "span", "src-tag src-" + fam, label);
  });
  if (isDoc) add(row, "div", "score kind-score", item.category_label || "资料");
  else add(row, "div", "score " + scoreClass(item.cvss), scoreText(item.cvss));
  var text = add(row, "div");
  var headline = item.title && item.title !== item.cve_id ? item.title : (item.description || "");
  add(text, "div", "desc", (headline || "").slice(0, 140));
  var product = item.product ? (" · " + item.product) : "";
  var pub = dateText(item.published_at);
  var collected = dateText(item.collected_at);
  var when = "发布 " + pub;
  // 入库日 ≠ 发布日：避免把「原文昨天公开」误读成「监测停在昨天」。
  if (item.collected_at && collected && collected !== pub && collected !== "未知") {
    when += " · 入库 " + collected;
  }
  add(text, "div", "meta", when + " · " + labels.join("、") + product);
}

function renderPrompts() {
  var promptBox = $("prompts");
  if (!promptBox) return;
  clear(promptBox);
  prompts.forEach(function (text) {
    var button = add(promptBox, "button", "", text);
    button.type = "button";
    button.addEventListener("click", function () {
      $("question").value = text;
    });
  });
}

function setOfflineMode(enabled) {
  if (offlineModeKnown && offlineDemo === !!enabled) return;
  offlineModeKnown = true;
  offlineDemo = !!enabled;
  if ($("offline-demo-banner")) $("offline-demo-banner").hidden = !offlineDemo;
  document.querySelectorAll("#library-sync, #enrich-btn, #sample-btn, #settings-form input, #settings-form button").forEach(function (control) {
    control.disabled = offlineDemo;
    control.title = offlineDemo ? "离线演示不调用外部服务；请使用已加载的样例证据。" : "";
  });
  if ($("settings-mode-hint")) $("settings-mode-hint").textContent = offlineDemo
    ? "离线演示已停用模型调用，不需要填写密钥。"
    : "真实密钥仅保存在当前环境，不会上传。";
  if ($("monitor-intro")) $("monitor-intro").textContent = offlineDemo
    ? "当前为合成样例，可浏览、筛选并按样例证据问答。手动刷新只同步本地样例。"
    : "自动汇聚漏洞与安全资料；可立即刷新，或等待定时更新。";
  if ($("enrich-status") && offlineDemo) $("enrich-status").textContent = "离线演示不查询外部风险源，可查看现有记录并评估演示资产。";
  if ($("library-sync-public-status") && offlineDemo) $("library-sync-public-status").textContent = "离线演示使用已加载的合成资料。";
  var reasoning = document.querySelector('#library-mode option[value="reasoning"]');
  if (reasoning) reasoning.disabled = offlineDemo;
  if (offlineDemo && $("library-mode") && $("library-mode").value === "reasoning") $("library-mode").value = "excerpt";
  if (offlineDemo) {
    prompts = [
      "CVE-2099-90002 的受影响版本是什么？",
      "CVE-2099-90003 的现有证据提到了什么风险？",
      "比较 CVE-2099-90002 和 CVE-2099-90003 的 CVSS 与受影响版本",
      "当前有哪些 vllm 相关的合成情报？"
    ];
    renderPrompts();
  }
  setPill(false);
}

function setPill(ready) {
  var pill = $("llm-pill");
  if (!pill) return;
  pill.textContent = offlineDemo
    ? "离线演示 · 问答摘录样例证据"
    : ready ? "大模型已配置" : "大模型未配置，问答先摘录原文";
}

function setView(name, opts) {
  opts = opts || {};
  clearError();
  if (name === "assets") name = "enrich";
  Object.keys(titles).forEach(function (key) {
    if ($(key)) $(key).hidden = key !== name;
  });
  if ($("assets")) $("assets").hidden = true;
  document.querySelectorAll(".pipeline button").forEach(function (button) {
    button.className = button.getAttribute("data-view") === name ? "is-on" : "";
  });
  $("page-title").textContent = titles[name] || name;
  if ($("page-eyebrow")) $("page-eyebrow").textContent = eyebrows[name] || "工作台";
  if (name === "overview") loadOverview();
  if (name === "monitor") {
    loadMonitorStatus();
    // Skip feed fetch while a refresh is in flight — avoids racing B monitor path.
    if (!monitorRefreshing && !opts.skipFeed) loadItems("monitor");
  }
  if (name === "enrich") loadItems(name);
  if (name === "risks") loadRisks().catch(showError);
  if (name === "ask") loadAsk();
  if (name === "library") loadLibrary();
  if (name === "enrich") loadAssets().catch(function () {});
  if (name === "settings") loadSettings();
}

function setTeamHealth(team) {
  var el = $("team-health");
  if (!el) return;
  if (team && team.enabled !== false && team.reachable === false) {
    el.hidden = false;
    var err = team.error || "";
    el.textContent = "部分情报来源暂不可用"
      + (err ? "：" + err : "")
      + "。仍可查看已有情报，并继续刷新 NVD / OSV。";
  } else {
    el.hidden = true;
    el.textContent = "";
  }
}

function statusClass(status) {
  var s = String(status || "");
  if (s === "接通" || s.indexOf("良好") === 0 || s.indexOf("合格") === 0 || s.indexOf("优秀") === 0 || s === "可演示") return "st-ok";
  if (s === "跳过") return "st-skip";
  if (s === "空" || s === "未配置") return "st-empty";
  if (s.indexOf("部分") === 0 || s === "部分可计") return "st-warn";
  return "st-bad";
}

function formatStamp(value) {
  if (!value) return "—";
  var text = String(value);
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) return text + "（仅日期）";
  // A naive timestamp has no known offset. Do not silently reinterpret it as
  // UTC or the browser's zone; source dates without a time remain dates.
  if (!/T.*(?:Z|[+-]\d{2}:?\d{2})$/i.test(text)) return text.replace("T", " ") + "（时区未标明）";
  var instant = new Date(text);
  if (!Number.isFinite(instant.getTime())) return text;
  var parts = {};
  new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Shanghai", year: "numeric", month: "2-digit",
    day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" })
    .formatToParts(instant).forEach(function (part) { parts[part.type] = part.value; });
  return parts.year + "-" + parts.month + "-" + parts.day + " "
    + parts.hour + ":" + parts.minute + ":" + parts.second + "（北京时间）";
}

function monitorCount(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? String(value) : "未提供";
}

function monitorResultLabel(status) {
  return {success: "成功", partial: "部分成功", failed: "失败", timeout: "超时", running: "进行中",
    skipped: "跳过", disabled: "未启用"}[status] || "状态未提供";
}

function sourceCoverageText(summary) {
  if (!summary) return "来源采集统计未提供";
  return "来源成功 " + monitorCount(summary.source_success) + "/" + monitorCount(summary.source_total)
    + " · 部分成功 " + monitorCount(summary.source_partial) + " · 失败 " + monitorCount(summary.source_failed)
    + " · 跳过 " + monitorCount(summary.source_skipped);
}

function collectionSummaryText(summary) {
  if (!summary) return "来源采集统计未提供；AI情报新增数不能代表全部来源结果。";
  var label = summary.counts_complete === true ? "来源记录新增 " : "已确认来源记录新增 ";
  return "最近来源采集 " + (summary.finished_at ? formatStamp(summary.finished_at) : "结束时间未提供")
    + "（" + monitorResultLabel(summary.status) + "） · " + label + monitorCount(summary.raw_inserted)
    + " · 来源记录更新 " + monitorCount(summary.raw_updated) + " · " + sourceCoverageText(summary)
    + (summary.counts_complete === false ? "。计数不完整，未上报来源可能已保存部分记录。" : "");
}

function renderCollectionSummary(summary) {
  var line = $("monitor-live-sources");
  if (line) line.textContent = collectionSummaryText(summary);
  var details = $("monitor-source-details"), list = $("monitor-source-list");
  if (!details || !list) return;
  var rows = summary && Array.isArray(summary.sources) ? summary.sources : [];
  details.hidden = rows.length === 0;
  clear(list);
  rows.forEach(function (row) {
    var message = sourceLabel(row.source) + "：" + monitorResultLabel(row.status)
      + " · 来源记录新增 " + monitorCount(row.inserted) + " · 更新 " + monitorCount(row.updated);
    if (row.recent_success === true) message += " · 最近发布采集成功";
    if (row.pending === true) message += " · 历史窗口仍待追赶";
    if (row.error) message += " · " + String(row.error).slice(0, 240);
    add(list, "p", "hint", message);
  });
}

function aiMonitorHeadline(data) {
  return "最近更新 " + formatStamp(data.last_run) + " · 上次AI情报新增 " + monitorCount(data.last_count)
    + " 条 · 上次刷新" + monitorResultLabel(data.last_status);
}

function stageStatusLabel(status) {
  if (status === "running") return { text: "进行中", cls: "st-run" };
  if (status === "ok") return { text: "完成", cls: "st-ok" };
  if (status === "skip") return { text: "跳过", cls: "st-skip" };
  if (status === "error") return { text: "失败", cls: "st-err" };
  if (status === "partial") return { text: "部分成功", cls: "st-err" };
  return { text: "等待", cls: "st-pend" };
}

function pipelineCountsPending(pipeline) {
  var metrics = (pipeline && pipeline.metrics) || {};
  return (pipeline && pipeline.status === "running")
    && !(metrics.hit || metrics.kept || metrics.inserted || metrics.merged || metrics.external_fetches);
}

function ensurePipelineStageEl(stagesEl, stage, index) {
  var existing = stagesEl.children[index];
  var wantId = stage.id || String(index);
  if (existing && existing.getAttribute("data-stage-id") === wantId) return existing;
  // Structure drift: rebuild from this index onward once.
  while (stagesEl.children.length > index) {
    stagesEl.removeChild(stagesEl.lastChild);
  }
  var li = document.createElement("li");
  li.setAttribute("data-stage-id", wantId);
  var top = document.createElement("div");
  top.className = "pipeline-stage-top";
  var title = document.createElement("span");
  title.className = "pipeline-stage-title";
  top.appendChild(title);
  var sub = document.createElement("span");
  sub.className = "pipeline-stage-sub";
  top.appendChild(sub);
  var stEl = document.createElement("span");
  stEl.className = "pipeline-stage-status";
  top.appendChild(stEl);
  li.appendChild(top);
  var note = document.createElement("p");
  note.className = "hint pipeline-stage-note";
  note.style.margin = "4px 0 0";
  note.hidden = true;
  li.appendChild(note);
  stagesEl.appendChild(li);
  return li;
}

function renderCollectPipeline(pipeline, opts) {
  opts = opts || {};
  var box = $("collect-pipeline");
  var stagesEl = $("pipeline-stages");
  var metricsEl = $("pipeline-metrics");
  var summaryEl = $("pipeline-summary");
  var techEl = $("pipeline-tech");
  var techBody = $("pipeline-tech-body");
  if (!box || !stagesEl) return;
  if (!pipeline || !(pipeline.stages || []).length) {
    if (!opts.forceShow) box.hidden = true;
    return;
  }
  box.hidden = false;
  var metrics = pipeline.metrics || {};
  var status = pipeline.status || "";
  var countsPending = pipelineCountsPending(pipeline);
  if (summaryEl) {
    if (status === "running") {
      summaryEl.textContent = "监测刷新中"
        + (pipeline.elapsed_sec != null ? "（已 " + pipeline.elapsed_sec + " 秒）" : "")
        + (countsPending
          ? "——请求进行中，本轮统计待阶段结束。"
          : "——下方为已汇总的本轮统计。");
    } else if (pipeline.summary) {
      summaryEl.textContent = pipeline.summary;
    } else {
      summaryEl.textContent = "下方是AI情报同步统计；来源采集结果见上方。AI情报新增为0不代表各来源没有新记录。";
    }
  }
  if (metricsEl) {
    var bits = [];
    if (pipeline.elapsed_sec != null && status !== "idle") {
      bits.push("耗时 <strong>" + pipeline.elapsed_sec + "s</strong>");
    }
    // Avoid flashing zeros while collectors are still running — that looked like "搜空".
    if (countsPending) {
      bits.push("<em>本轮统计待阶段结束</em>");
      if (metrics.failures) bits.push("失败 <strong>" + metrics.failures + "</strong>");
    } else {
      bits.push("AI同步返回 <strong>" + monitorCount(metrics.hit) + "</strong>");
      bits.push("AI同步水位后保留 <strong>" + monitorCount(metrics.kept) + "</strong>");
      bits.push("AI情报新增 <strong>" + monitorCount(metrics.inserted) + "</strong>");
      bits.push("AI情报合并 <strong>" + monitorCount(metrics.merged) + "</strong>");
      bits.push("流程失败阶段 <strong>" + monitorCount(metrics.failures) + "</strong>");
      if (metrics.external_fetches) {
        bits.push("外部请求 <strong>" + metrics.external_fetches + "</strong>");
      }
    }
    var nextHtml = bits.join("<span aria-hidden=\"true\"> · </span>");
    if (metricsEl.getAttribute("data-html") !== nextHtml) {
      metricsEl.setAttribute("data-html", nextHtml);
      metricsEl.innerHTML = nextHtml;
    }
    metricsEl.hidden = false;
  }
  // In-place stage updates — avoid clear()+rebuild flicker and CSS re-entry animation.
  var stages = pipeline.stages || [];
  stages.forEach(function (stage, index) {
    var li = ensurePipelineStageEl(stagesEl, stage, index);
    var st = stage.status || "pending";
    var nextClass = "pipeline-stage is-" + st;
    if (li.className !== nextClass) li.className = nextClass;
    var title = li.querySelector(".pipeline-stage-title");
    var sub = li.querySelector(".pipeline-stage-sub");
    var stEl = li.querySelector(".pipeline-stage-status");
    var note = li.querySelector(".pipeline-stage-note");
    if (title) title.textContent = stage.title || stage.id || "";
    var subText = "";
    if (stage.got || stage.produced) {
      subText = [stage.got, stage.produced].filter(Boolean).join(" · ");
    } else if (stage.subtitle && st === "pending") {
      subText = stage.subtitle;
    } else if (stage.did && st === "running") {
      subText = stage.did;
    }
    if (sub) {
      sub.textContent = subText;
      sub.hidden = !subText;
    }
    var badge = stageStatusLabel(st);
    if (stEl) {
      stEl.className = "pipeline-stage-status " + badge.cls;
      stEl.textContent = badge.text;
    }
    if (note) {
      if (stage.note && (st === "ok" || st === "error" || st === "skip")) {
        note.hidden = false;
        note.textContent = stage.note;
      } else {
        note.hidden = true;
        note.textContent = "";
      }
    }
  });
  while (stagesEl.children.length > stages.length) {
    stagesEl.removeChild(stagesEl.lastChild);
  }
  if (techEl && techBody) {
    var tech = pipeline.tech_detail || "";
    if (tech) {
      techEl.hidden = false;
      techBody.textContent = tech;
    } else {
      techEl.hidden = true;
      techBody.textContent = "";
    }
  }
}

function renderMonitorLive(data, opts) {
  opts = opts || {};
  // Merge poll/tick fragments onto last known status so null ticks do not wipe clocks.
  if (data) lastMonitorStatus = data;
  else data = lastMonitorStatus;
  var live = $("monitor-live");
  var stateEl = $("monitor-live-state");
  var lastEl = $("monitor-live-last");
  var nextEl = $("monitor-live-next");
  var phaseEl = $("monitor-live-phase");
  var progress = $("monitor-progress");
  if (!live || !stateEl) return;
  var running = !!(opts.running || (data && data.running) || monitorRefreshing);
  var phase = opts.phase || (data && data.run_phase) || "";
  var elapsed = opts.elapsedSec != null ? opts.elapsedSec : null;
  var minutes = (data && data.interval_minutes) || ((data && data.interval_hours) ? data.interval_hours * 60 : 15);
  var intervalText = minutes < 60 ? (minutes + " 分钟") : ((minutes / 60) + " 小时");
  live.classList.toggle("is-running", running);
  if (progress) progress.hidden = !running;
  // One primary clock: last collect → next scheduled refresh (not item publish age).
  if (running) {
    stateEl.textContent = "正在刷新" + (elapsed != null ? "（已 " + elapsed + " 秒）" : "") + "…";
    if (phaseEl) {
      phaseEl.textContent = phase
        ? ("当前步骤：" + phase)
        : "监测刷新中…";
    }
  } else {
    stateEl.textContent = data && data.last_status ? "空闲 · 上次刷新" + monitorResultLabel(data.last_status) : "空闲";
    if (phaseEl) {
      phaseEl.textContent = offlineDemo ? "离线样例已加载；手动刷新只同步本地样例。"
        : data && data.auto_enabled === false ? "自动监测已关闭；可手动刷新。"
        : "约 " + intervalText + " 后自动刷新，也可立即刷新。";
    }
  }
  if (lastEl && data) {
    var last = data.last_run || "";
    lastEl.textContent = last
      ? (formatStamp(last) + " · 上次AI情报新增 " + monitorCount(data.last_count) + " 条")
      : (offlineDemo ? "离线样例已就绪" : "尚未刷新；可点「立即刷新一轮」");
  }
  renderCollectionSummary(data && data.collection_summary);
  if (nextEl) {
    if (running) nextEl.textContent = "本轮进行中…";
    else if (offlineDemo) nextEl.textContent = "离线演示不执行定时采集";
    else if (data && data.auto_enabled === false) nextEl.textContent = "自动监测已关闭";
    else if (data && data.next_run) nextEl.textContent = formatStamp(data.next_run) + "（等待约 " + intervalText + "）";
    else if (data) nextEl.textContent = "完成首轮后等待约 " + intervalText;
  }
  var pipe = opts.pipeline || null;
  if (!pipe && data && data.pipeline) {
    // While a refresh is in flight, do not paint a stale completed/idle pipeline
    // (all-zero metrics) over the in-progress shell — wait for a running poll.
    var staleDone = monitorRefreshing && running
      && data.pipeline.status !== "running";
    if (!staleDone) pipe = data.pipeline;
  }
  if (pipe) {
    if (running && elapsed != null) {
      pipe = {
        status: pipe.status,
        started_at: pipe.started_at,
        finished_at: pipe.finished_at,
        elapsed_sec: pipe.elapsed_sec != null ? pipe.elapsed_sec : elapsed,
        metrics: pipe.metrics,
        stages: pipe.stages,
        summary: pipe.summary,
        tech_detail: pipe.tech_detail,
      };
    }
    renderCollectPipeline(pipe, {
      forceShow: running || ["done", "partial", "error"].indexOf(pipe.status) !== -1,
    });
  }
}

function loadMonitorStatus() {
  return api("/api/monitor/status").then(function (data) {
    setOfflineMode(data.offline_demo);
    setTeamHealth(data.team);
    lastMonitorStatus = data;
    renderMonitorLive(data);
    if (monitorRefreshing) {
      // Keep the in-progress copy; only refresh the live panel timestamps.
      return data;
    }
    var bits = [];
    if (offlineDemo) bits.push("离线样例，仅同步本地数据");
    if (data.running) bits.push("正在刷新：" + (data.run_phase || "进行中"));
    else if (data.last_run) {
      bits.push("最近更新 " + formatStamp(data.last_run));
      bits.push("上次AI情报新增 " + monitorCount(data.last_count) + " 条");
      var pm = (data.pipeline && data.pipeline.metrics) || {};
      if (pm.hit != null) bits.push("AI同步返回 " + pm.hit);
      if (pm.kept != null) bits.push("AI同步水位后保留 " + pm.kept);
      if (pm.merged != null) bits.push("AI情报合并 " + pm.merged);
      bits.push(collectionSummaryText(data.collection_summary));
    } else bits.push("尚未刷新；可点「立即刷新一轮」");
    if (!data.running && data.next_run) bits.push("下次刷新 " + formatStamp(data.next_run));
    if (data.last_error) bits.push("上次错误：" + data.last_error);
    if (data.last_status) bits.push("上次结果：" + monitorResultLabel(data.last_status));
    if ((data.last_warnings || []).length && !data.last_error) bits.push("上次提示：" + data.last_warnings[0]);
    setMonitorStatus(bits.join(" · ") + "。");
    var line = $("monitor-line");
    if (line) {
      line.textContent = data.running
        ? ("监测进行中：" + (data.run_phase || "刷新中") + "…")
        : (data.last_run
          ? (aiMonitorHeadline(data) + " · " + sourceCoverageText(data.collection_summary))
          : "可点「立即刷新监测」马上跑一轮");
    }
    return data;
  }).catch(function (error) {
    if (!monitorRefreshing) {
      setMonitorStatus("无法读取自动监测状态：" + (error.message || "请求失败"));
    }
  });
}

function loadOverview() {
  api("/api/overview").then(function (data) {
    setOfflineMode(data.offline_demo);
    setPill(data.llm_ready);
    var stats = $("stats");
    clear(stats);
    var monitor = data.monitor || {};
    var team = data.team_intel || {};
    var sourceNames = (data.sources || []).slice(0, 6).map(sourceLabel);
    var running = monitor.running ? "正在刷新" : (monitor.last_run
      ? aiMonitorHeadline(monitor) + " · " + sourceCoverageText(monitor.collection_summary) : "可点监测页立即刷新");
    $("monitor-line").textContent =
      "监测 · " + running +
      " · 情报 " + data.items +
      " · 资料 " + ((data.library || {}).documents || 0) +
      (sourceNames.length ? " · 来源 " + sourceNames.join(" / ") : "") +
      " · 模型 " + (offlineDemo ? "离线停用" : data.llm_ready ? "已配置" : "未配置");
    [
      [String(data.items), "情报条目"],
      [String(data.source_count || 0), "漏洞来源数"],
      [String((data.library || {}).documents || 0), "资料库文档"],
      [team.reachable ? String(team.team_total != null ? team.team_total : "—") : "—", "多源 CVE"],
      [offlineDemo ? "离线摘录" : data.llm_ready ? "可用" : "未配置", "问答模型"]
    ].forEach(function (pair) {
      var card = add(stats, "div", "stat");
      add(card, "b", "", pair[0]);
      add(card, "span", "", pair[1]);
    });
    var recent = $("recent");
    clear(recent);
    if (!data.recent.length) {
      add(recent, "p", "empty", "情报库还是空的。请到「情报监测」点立即刷新。");
    }
    var recentMeta = pageSlice(data.recent || [], "recent", OVERVIEW_PAGE_SIZE);
    recentMeta.items.forEach(function (item) {
      renderItemRow(recent, item, function (row) { openDetail(row.cve_id || row.id); });
    });
    renderPager(recent, "recent", recentMeta, function () { loadOverview(); });
    var stepsTarget = $("steps");
    var stepRows = data.steps || [];
    var stepsMeta = pageSlice(stepRows, "steps", OVERVIEW_PAGE_SIZE);
    renderSteps(stepsTarget, stepsMeta.items);
    renderPager(stepsTarget, "steps", stepsMeta, function () { loadOverview(); });
  }).catch(showError);
}

var monitorScope = "all";
var monitorCategoryFilter = "all";
var monitorSourceFilter = "all";
var lastMonitorFeed = null;

var CATEGORY_FILTER_LABELS = {
  all: "全部分类",
  vendor: "厂商公告",
  paper: "论文",
  community: "社区/博客",
  standard: "标准/政策"
};
var SOURCE_FILTER_LABELS = {
  all: "全部来源",
  nvd: "NVD",
  osv: "OSV",
  github: "GitHub",
  kev: "CISA KEV",
  vendor: "厂商公告源",
  community: "社区",
  blog: "博客",
  paper: "论文",
  standard: "标准/政策"
};

function setMonitorScope(scope) {
  monitorScope = scope || "all";
  listPages.monitor = 1;
  document.querySelectorAll("[data-monitor-scope]").forEach(function (node) {
    node.className = node.getAttribute("data-monitor-scope") === monitorScope ? "chip is-on" : "chip";
  });
  var detail = $("monitor-detail");
  if (detail) {
    clear(detail);
    add(detail, "p", "empty", "点左侧一条情报查看摘要。漏洞可送去「情报富集」；资料可打开「资料库」。");
  }
  loadItems("monitor");
}
window.setMonitorScope = setMonitorScope;

function setMonitorCategoryFilter(filter) {
  monitorCategoryFilter = filter || "all";
  listPages.monitor = 1;
  document.querySelectorAll("[data-category-filter]").forEach(function (node) {
    node.className = node.getAttribute("data-category-filter") === monitorCategoryFilter ? "chip is-on" : "chip";
  });
  if (lastMonitorFeed) renderMonitorFeed(lastMonitorFeed);
  else loadItems("monitor");
}
window.setMonitorCategoryFilter = setMonitorCategoryFilter;

function setMonitorSourceFilter(filter) {
  monitorSourceFilter = filter || "all";
  listPages.monitor = 1;
  document.querySelectorAll("[data-source-filter]").forEach(function (node) {
    node.className = node.getAttribute("data-source-filter") === monitorSourceFilter ? "chip is-on" : "chip";
  });
  if (lastMonitorFeed) renderMonitorFeed(lastMonitorFeed);
  else loadItems("monitor");
}
window.setMonitorSourceFilter = setMonitorSourceFilter;

function monitorKeyword() {
  var keywordEl = $("keyword");
  var filterEl = $("filter");
  var value = keywordEl ? keywordEl.value.trim() : "";
  if (filterEl) filterEl.value = value;
  return value;
}

function setMonitorStatus(text) {
  var status = $("auto-monitor-status");
  if (status) status.textContent = text;
}

function renderMonitorFeed(data) {
  var target = $("monitor-list");
  clear(target);
  var allItems = data.items || [];
  var items = allItems.filter(function (item) {
    return itemMatchesCategoryFilter(item, monitorCategoryFilter)
      && itemMatchesSourceFilter(item, monitorSourceFilter);
  });
  var counts = data.counts || {};
  var summary = $("monitor-summary");
  var teamTotal = (((data.team_documents || {}).total) || 0);
  var teamMeta = data.team_documents || {};
  if (teamMeta.enabled === false) {
    setTeamHealth(teamMeta);
  } else if (teamMeta.reachable === false) {
    setTeamHealth({
      reachable: false,
      error: teamMeta.error || "资料摘要探测失败",
    });
  }
  if (summary) {
    var filterBits = [];
    if (monitorCategoryFilter !== "all") {
      filterBits.push("分类「" + (CATEGORY_FILTER_LABELS[monitorCategoryFilter] || monitorCategoryFilter) + "」");
    }
    if (monitorSourceFilter !== "all") {
      filterBits.push("来源「" + (SOURCE_FILTER_LABELS[monitorSourceFilter] || monitorSourceFilter) + "」");
    }
    var before = counts.cve_before_window;
    summary.textContent = "展示窗：漏洞 " + (counts.cve || 0)
      + " · 资料 " + (counts.document || 0)
      + (before != null && before > (counts.cve || 0)
        ? "（知识库侧匹配漏洞 " + before + "，流内按组件截断）" : "")
      + (teamTotal ? "（资料摘要 " + teamTotal + "）" : "")
      + (filterBits.length ? " · " + filterBits.join(" + ") + " → 显示 " + items.length + " 条" : "")
      + "。条目「发布」= 原文日；监测是否在跑看上方「最近更新」。";
  }
  var mixEl = $("monitor-mix");
    if (mixEl) {
    var comp = data.composition || {};
    var byCat = comp.by_category || {};
    var byProd = comp.by_product || {};
    var catBits = Object.keys(byCat).slice(0, 6).map(function (k) {
      return k + " " + byCat[k];
    });
    var prodBits = Object.keys(byProd).slice(0, 6).map(function (k) {
      return k + " " + byProd[k];
    });
    var ollamaShare = typeof comp.ollama_share === "number" ? Math.round(comp.ollama_share * 100) : null;
    var parts = [];
    if (catBits.length) parts.push("分类：" + catBits.join("、"));
    if (prodBits.length) parts.push("组件：" + prodBits.join("、"));
    if (ollamaShare != null) parts.push("提及 Ollama 约 " + ollamaShare + "%");
    if (data.window_note) parts.push(data.window_note);
    if (data.mix_note) parts.push(data.mix_note);
    var fresh = data.freshness || {};
    if (fresh.newest_published_at) {
      parts.push("流内最新发布 " + dateText(fresh.newest_published_at)
        + (fresh.newest_collected_at ? " · 最新入库 " + dateText(fresh.newest_collected_at) : ""));
    }
    mixEl.textContent = parts.join(" · ");
    mixEl.hidden = !parts.length;
  }
  var query = monitorKeyword();
  if (!items.length) {
    var empty = add(target, "p", "empty", "");
    if ((monitorCategoryFilter !== "all" || monitorSourceFilter !== "all") && allItems.length) {
      empty.textContent = "当前分类/来源筛选下没有条目。可点「全部分类」与「全部来源」查看完整情报流。";
    } else if (query) {
      empty.textContent = "没有匹配「" + query + "」的条目。可清除关键词或换词后刷新。";
      var clearBtn = add(target, "button", "ghost", "清除关键词并显示全部");
      clearBtn.type = "button";
      clearBtn.addEventListener("click", function () {
        if ($("keyword")) $("keyword").value = "";
        if ($("filter")) $("filter").value = "";
        loadItems("monitor");
      });
    } else {
      empty.textContent = offlineDemo
        ? "离线样例未加载，请检查离线启动结果。"
        : "情报流还是空的。请点「立即刷新一轮」。若仍空，可能是未初始化演示库或外网不可达。";
    }
    return data;
  }
  var meta = pageSlice(items, "monitor", LIST_PAGE_SIZE);
  meta.items.forEach(function (item) {
    renderItemRow(target, item, function (row) { openMonitorDetail(row); });
  });
  renderPager(target, "monitor", meta, function () {
    if (lastMonitorFeed) renderMonitorFeed(lastMonitorFeed);
  });
  return data;
}

function loadItems(view) {
  var query = view === "monitor" ? monitorKeyword() : "";
  if (view === "monitor") {
    var listEl = $("monitor-list");
    var winY = window.scrollY || document.documentElement.scrollTop || 0;
    var listY = listEl ? listEl.scrollTop : 0;
    return api("/api/monitor/feed?kind=" + encodeURIComponent(monitorScope) + (query ? "&q=" + encodeURIComponent(query) : "")).then(function (data) {
      lastMonitorFeed = data;
      var result = renderMonitorFeed(data);
      if (listEl) listEl.scrollTop = listY;
      window.scrollTo(0, winY);
      if (selectedMonitorId && listEl) {
        var row = listEl.querySelector('[data-item-id="' + selectedMonitorId + '"]');
        if (row) row.classList.add("is-selected");
      }
      return result;
    }).catch(function (error) {
      if (monitorRefreshing) {
        // Soft-fail during in-flight refresh; final loadItems after run will retry.
        setMonitorStatus("监测进行中，情报流稍后自动刷新…");
        return null;
      }
      showError(error);
      setMonitorStatus("刷新情报流失败：" + (error.message || "请求失败"));
      throw error;
    });
  }
  return api("/api/items" + (query ? "?q=" + encodeURIComponent(query) : "")).then(function (data) {
    var target = $("enrich-list");
    clear(target);
    if (!data.items.length) {
      add(target, "p", "empty", "没有匹配的情报。");
      return data;
    }
    var meta = pageSlice(data.items, "enrich", LIST_PAGE_SIZE);
    meta.items.forEach(function (item) {
      renderItemRow(target, item, function (row) { openDetail(row.cve_id || row.id); });
    });
    renderPager(target, "enrich", meta, function () { loadItems("enrich"); });
    return data;
  }).catch(showError);
}

function openMonitorDetail(item) {
  if (!item) return;
  selectedMonitorId = String(item.cve_id || item.id || item.url || "");
  var listEl = $("monitor-list");
  if (listEl) {
    listEl.querySelectorAll(".row.is-selected").forEach(function (node) {
      node.classList.remove("is-selected");
    });
    var row = selectedMonitorId
      ? listEl.querySelector('[data-item-id="' + selectedMonitorId.replace(/"/g, "") + '"]')
      : null;
    if (row) row.classList.add("is-selected");
  }
  if (item.kind === "document") {
    var panel = $("monitor-detail");
    clear(panel);
    add(panel, "h2", "", (item.category_label || "资料") + (item.demo ? "（演示）" : ""));
    add(panel, "p", "desc", item.title || "");
    add(panel, "p", "desc", item.description || "（列表摘要；完整正文见资料存档）");
    var fields = add(panel, "div", "fields");
    [
      ["类型", item.category_label || item.category || "资料"],
      ["来源", itemSourceLabels(item).join("、")],
      ["记录类型", item.demo ? "演示合成" : "联网采集"]
    ].forEach(function (pair) {
      var field = add(fields, "div", "field");
      add(field, "span", "", pair[0]);
      add(field, "b", "", pair[1]);
    });
    if (item.url) {
      var link = add(panel, "a", "meta", item.url);
      link.href = item.url; link.target = "_blank"; link.rel = "noopener";
    }
    var goLib = add(panel, "button", "ghost", "打开资料存档");
    goLib.type = "button";
    goLib.addEventListener("click", function () { setView("library"); });
    return;
  }
  var cveId = item.cve_id || item.id;
  clearError();
  showToast("正在加载「" + cveId + "」…", "busy");
  api("/api/items/" + encodeURIComponent(cveId)).then(function (detail) {
    var panel = $("monitor-detail");
    clear(panel);
    add(panel, "h2", "", detail.cve_id + (isDemoItem(detail) || detail.demo ? "（演示）" : ""));
    add(panel, "p", "desc", detail.title || "");
    add(panel, "p", "desc", detail.description || "");
    var fields = add(panel, "div", "fields");
    [
      ["类型", "漏洞 CVE"],
      ["来源", itemSourceLabels(detail).join("、")],
      ["产品", missingText(detail.product, "未写明")],
      ["受影响版本", (detail.affected || []).length ? (detail.affected || []).join("、") : "未写明"],
      ["CVSS", scoreText(detail.cvss) + (detail.severity ? " · " + detail.severity : "")],
      ["记录类型", isDemoItem(detail) ? "演示合成" : "联网/入库情报"]
    ].forEach(function (pair) {
      var field = add(fields, "div", "field");
      add(field, "span", "", pair[0]);
      add(field, "b", "", pair[1]);
    });
    var go = add(panel, "button", "primary", "送去富集（含影响资产）");
    go.type = "button";
    go.addEventListener("click", function () { openDetail(cveId); });
    showToast("已打开 " + detail.cve_id, "ok");
  }).catch(function (error) {
    showError(error);
    showToast("加载详情失败：" + (error.message || "请求失败"), "error");
  });
}

var detailRequestVersion = 0;
function openDetail(cveId) {
  var requestVersion = ++detailRequestVersion;
  setView("enrich");
  clearError();
  showToast("正在加载「" + cveId + "」详情…", "busy");
  api("/api/items/" + encodeURIComponent(cveId)).then(function (detail) {
    if (requestVersion !== detailRequestVersion) return;
    if (!detail || detail.cve_id !== cveId) throw new Error("详情返回的 CVE 与请求不一致，未采用该响应。");
    renderDetail(detail);
    showToast("已打开 " + cveId, "ok");
  }).catch(function (error) {
    if (requestVersion !== detailRequestVersion) return;
    showError(error);
    showToast("加载详情失败：" + (error.message || "请求失败"), "error");
  });
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
  (report.weaknesses || []).forEach(function (row) {
    fact("弱点分类：" + row.cwe_id + "；提供者 " + (row.provider || "未提供"), row.evidence_ids);
  });
  (report.attack_conditions || []).concat(report.technical_impact || []).forEach(function (row) { fact("评分向量解释 · " + row.label + "：" + row.text, row.evidence_ids); });
  (report.fix_records || []).forEach(function (row) { fact("修复记录：" + row.title + "；修复效果尚未由本项目测试。", row.evidence_ids); });
  (report.poc_candidates || []).forEach(function (row) { fact("利用代码候选：" + row.url + "；本项目未运行复现。", row.evidence_ids); });
  var taxonomy = report.risk_taxonomy;
  if (taxonomy && (taxonomy.items || []).length) {
    add(section, "h4", "", "AI 风险机制分类候选");
    taxonomy.items.forEach(function (row) {
      var labels = (row.owasp || []).concat(row.mitre_atlas || []).map(function (label) {
        return label.id + " · " + label.name;
      });
      fact(row.mechanism + " · " + labels.join("；"), row.evidence_ids);
      add(section, "p", "meta", row.match_reason || "根据已存档描述生成，需人工复核。");
    });
    if (taxonomy.notice) add(section, "p", "meta", taxonomy.notice);
  }
  var history = report.historical_relations;
  if (history) {
    add(section, "h4", "", "历史漏洞关联线索");
    (history.items || []).forEach(function (row) {
      var reasons = (row.match_basis || []).map(function (basis) {
        if (basis.kind === "same_component") return "相同组件 " + basis.vendor + "/" + basis.product;
        if (basis.kind === "same_weakness") return "相同弱点 " + basis.cwe_id;
        if (basis.kind === "published_before_target") return "发布时间早于当前漏洞";
        return "";
      }).filter(Boolean);
      fact(row.cve_id + " · " + reasons.join("；"), row.evidence_ids);
    });
    add(section, "p", "meta", history.detail || "本地存档暂无历史关联线索。");
    if (history.notice) add(section, "p", "meta", history.notice);
  }
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

function renderArticleCandidates(panel, cveId) {
  var section = add(panel, "div", "article-candidates");
  add(section, "h3", "", "论文与分析文章关联候选");
  add(section, "p", "meta", "只查询已入库资料。候选需结合原文核对，不用于改写评分、版本、修复或资产结论。");
  var button = add(section, "button", "ghost", "查看本地关联候选");
  button.type = "button";
  var content = add(section, "div", "");
  button.addEventListener("click", function () {
    button.disabled = true;
    button.textContent = "正在检索本地资料…";
    api("/api/article-candidates/" + encodeURIComponent(cveId)).then(function (report) {
      if (panel.querySelector(".article-candidates") !== section) return;
      clear(content);
      add(content, "p", "meta", report.detail || report.notice);
      (report.warnings || []).forEach(function (text) { add(content, "p", "meta", text); });
      (report.items || []).forEach(function (row) {
        var block = add(content, "details", "guidance-fact");
        add(block, "summary", "", (row.category === "paper" ? "论文 · " : "分析文章 · ") + row.title);
        add(block, "span", "tag", row.explicit_cve_mention ? "完整编号提及 · 未审核候选" : "机制 / CWE 关联候选 · 未审核");
        add(block, "p", "meta", row.association_notice);
        var scopes = {abstract: "论文摘要", full_text_html: "HTML 提取正文", article_body: "文章提取正文", team_summary: "接口摘要（非原始全文）"};
        add(block, "p", "meta", "资料范围：" + (scopes[row.content_scope] || missingText(row.content_scope, "未写明")) + " · 获取于 " + dateText(row.retrieved_at));
        if (row.retained_previous) add(block, "p", "meta", "最近更新失败，沿用上述日期的成功存档。");
        (row.match_basis || []).forEach(function (basis) { add(block, "p", "meta", basis.label + "（" + basis.term + "） · " + basis.citation_id); });
        (row.evidence || []).forEach(function (chunk) {
          add(block, "p", "desc", chunk.text);
          var link = add(block, "a", "meta", "引用片段：" + chunk.citation_id);
          link.href = chunk.url; link.target = "_blank"; link.rel = "noopener";
          add(block, "p", "meta", chunk.locator + " · 快照 SHA256：" + chunk.source_response_sha256);
        });
      });
      add(content, "p", "meta", report.notice);
      button.textContent = "重新检索本地关联候选";
    }).catch(function (error) {
      if (panel.querySelector(".article-candidates") !== section) return;
      clear(content);
      add(content, "p", "meta", error.message || "候选检索未完成，请稍后重试。");
      button.textContent = "重试本地关联候选";
    }).then(function () { button.disabled = false; });
  });
}


function renderPocCode(panel, cveId, initialReport) {
  var section = add(panel, "div", "poc-code");
  add(section, "h3", "", "PoC 代码搜集与静态审查");
  add(section, "p", "meta", "静态审查不证明可运行、利用成功或 RCE 已复现。本项目未执行这些代码。");
  var localButton = add(section, "button", "ghost", "查看本地代码审查记录");
  localButton.type = "button";
  var collectButton = add(section, "button", "ghost", "收集并静态审查代码");
  collectButton.type = "button";
  add(section, "p", "meta", "收集按钮仅下载预先登记、固定提交版本的 GitHub 文本文件；不安装依赖、不运行 PoC。其他漏洞需先登记候选来源。");
  var content = add(section, "div", "poc-code-content"), requestVersion = 0;
  function text(value, fallback) {
    if (value === undefined || value === null || value === "") return fallback || "未提供";
    return typeof value === "object" ? JSON.stringify(value) : String(value);
  }
  function reference(parent, label, url) {
    if (typeof url === "string" && !/[\u0000-\u0020\u007f\\]/.test(url)
        && (/^https:\/\/[^/?#]+(?:[/?#]|$)/i.test(url) || /^\/(?!\/)/.test(url))) {
      var link = add(parent, "a", "meta", label);
      link.href = url; link.target = "_blank"; link.rel = "noopener";
    } else add(parent, "p", "meta", label);
  }
  function location(row) {
    return text(row.file || row.path, "文件未提供") + " · 行号：" + text(row.lines || row.locator, "未提供");
  }
  function repositoryUrl(value) {
    return typeof value === "string" && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value) ? "https://github.com/" + value : value;
  }
  function draw(report) {
    clear(content);
    if (!report || report.cve_id !== cveId || !Array.isArray(report.items)) {
      add(content, "p", "meta", "代码审查记录格式或 CVE 不匹配，未采用该响应。");
      return;
    }
    var labels = {static_reviewed: "开发阶段静态审查记录已保存（未运行）", collected: "代码文件已收集（未运行）", partial: "部分文件未完成", error: "收集或审查失败", not_collected: "尚未收集代码", unconfigured: "尚未登记候选来源", not_configured: "尚未登记候选来源", not_found: "暂无本地记录", stale: "当前记录需重新核对"};
    add(content, "p", "desc", "记录状态：" + (labels[report.status] || text(report.status, "状态未提供，不能判为成功")));
    if (report.detail) add(content, "p", "meta", text(report.detail));
    if (report.retained_previous || report.stale) add(content, "p", "meta", "当前显示保留的历史记录；本次状态不能证明最新来源仍一致。");
    var attempt = report.latest_attempt;
    if (attempt) {
      add(content, "p", "meta", "最近收集尝试：" + text(attempt.status) + " · " + text(attempt.queried_at || attempt.at || attempt.attempted_at || attempt.retrieved_at));
      if (attempt.detail || attempt.error) add(content, "p", "meta", text(attempt.detail || attempt.error));
      if (attempt.error_type) add(content, "p", "meta", "失败类型：" + text(attempt.error_type));
    }
    if (!report.items.length) add(content, "p", "meta", "暂无可展示的代码审查记录；这不表示没有公开 PoC，也不表示漏洞已经验证。");
    report.items.forEach(function (row) {
      var block = add(content, "details", "guidance-fact");
      add(block, "summary", "", text(row.candidate_id, "候选代码"));
      add(block, "p", "desc", "静态记录状态：" + (labels[row.status] || text(row.status)) + " · 运行验证：" + (row.validation === "not_run" ? "not_run（未运行）" : text(row.validation, "未提供，不能判为已验证")));
      add(block, "p", "meta", "本项目未执行 PoC；静态记录不能作为可用性或漏洞复现结论。");
      if (row.detail) add(block, "p", "meta", text(row.detail));
      if (row.retrieved_at) add(block, "p", "meta", "来源文件获取时间：" + text(row.retrieved_at));
      if (row.retained_previous) add(block, "p", "meta", "该候选本次收集失败，保留上次通过完整性检查的来源记录。");
      reference(block, "仓库：" + text(row.repository), row.repository_url || repositoryUrl(row.repository));
      if (row.parent_repository) reference(block, "原始仓库：" + text(row.parent_repository), repositoryUrl(row.parent_repository));
      if (row.license || row.copyright) add(block, "p", "meta", "许可证：" + text(row.license) + " · 版权：" + text(row.copyright));
      add(block, "p", "meta", "固定提交 SHA：" + text(row.commit_sha));
      (Array.isArray(row.files) ? row.files : []).forEach(function (file) {
        var fileBlock = add(block, "div", "field");
        reference(fileBlock, "文件：" + text(file.path), file.url);
        add(fileBlock, "p", "meta", "字节数：" + text(file.size) + " · SHA-256：" + text(file.sha256));
        var syntaxLabels = {valid: "语法可解析（未运行）", invalid: "语法解析失败（未运行）"};
        add(fileBlock, "p", "meta", "Git blob SHA：" + text(file.git_blob_sha) + " · 语法检查：" + (syntaxLabels[file.syntax_status] || text(file.syntax_status, "未检查")));
      });
      var dependencies = Array.isArray(row.dependencies) ? row.dependencies : [];
      add(block, "p", "meta", "依赖（仅来源声明，未安装或验证）：" + (dependencies.length ? dependencies.map(function (dependency) { return text(dependency && dependency.declaration || dependency); }).join("；") : "来源未声明"));
      dependencies.forEach(function (dependency) {
        if (!dependency || typeof dependency !== "object") return;
        add(block, "p", "meta", "依赖声明位置：" + text(row.review && row.review.dependencies_file, "依赖文件未提供") + " · 行号：" + text(dependency.line));
        (dependency.evidence_ids || []).forEach(function (id) {
          var evidence = (report.evidence || []).find(function (entry) { return entry.citation_id === id; });
          reference(block, "依赖引用：" + id, evidence && evidence.url);
        });
      });
      var review = row.review || {};
      if (review.summary) add(block, "p", "desc", "静态审查摘要：" + text(review.summary));
      var capabilities = {file_read_attempt: "文件读取尝试"};
      if (review.capability) add(block, "p", "desc", "代码能力说明（静态判断）：" + (capabilities[review.capability] || text(review.capability)));
      var reviewers = {development_agent: "开发阶段代码审查"}, methods = {manual_source_read_and_ast: "逐行阅读与 AST 语法解析（未执行）"};
      add(block, "p", "meta", "审查者：" + (reviewers[review.reviewed_by] || text(review.reviewed_by)) + " · 方法：" + (methods[review.review_method] || text(review.review_method)));
      (Array.isArray(review.findings) ? review.findings : []).forEach(function (finding) {
        add(block, "p", "desc", text(finding.text));
        add(block, "p", "meta", location(finding));
        (finding.evidence_ids || []).forEach(function (id) {
          var evidence = (report.evidence || []).find(function (entry) { return entry.citation_id === id; });
          reference(block, "审查引用：" + id, evidence && evidence.url);
        });
      });
      if (review.target_version_claim) {
        add(block, "p", "desc", "代码来源声明的适用版本（未经运行确认）：" + text(review.target_version_claim.version));
        add(block, "p", "meta", location(review.target_version_claim));
      }
      (Array.isArray(review.notes) ? review.notes : review.notes ? [review.notes] : []).forEach(function (note) { add(block, "p", "meta", text(note)); });
      (row.evidence_ids || []).forEach(function (id) {
        var evidence = (report.evidence || []).find(function (entry) { return entry.citation_id === id; });
        if (!evidence) { add(block, "p", "meta", "缺少引用片段：" + id); return; }
        var excerpt = add(block, "details", "");
        var evidenceKinds = {poc_source_metadata: "来源元数据", poc_source_declaration: "来源声明摘录", development_static_review: "开发阶段静态审查记录"};
        add(excerpt, "summary", "meta", (evidenceKinds[evidence.text_kind] || "代码来源引用") + "：" + id);
        add(excerpt, "p", "desc", text(evidence.text));
        reference(excerpt, id, evidence.url);
        add(excerpt, "p", "meta", "位置：" + text(evidence.locator) + " · 证据绑定摘要：" + text(evidence.source_response_sha256 || evidence.sha256));
      });
    });
    (report.warnings || []).concat(report.limitations || []).forEach(function (warning) { add(content, "p", "meta", text(warning)); });
  }
  function request(collect) {
    var version = ++requestVersion;
    localButton.disabled = true; collectButton.disabled = true;
    clear(content);
    add(content, "p", "meta", collect ? "正在下载登记的文本文件并静态审查；不执行代码…" : "正在读取本地代码审查记录…");
    function current() { return version === requestVersion && panel.querySelector(".poc-code") === section; }
    api("/api/poc-code/" + encodeURIComponent(cveId) + (collect ? "/collect" : ""), collect ? {method: "POST"} : undefined).then(function (data) {
      if (!current()) return;
      draw(data && (data.poc_code || data.report) || data);
    }).catch(function (error) {
      if (!current()) return;
      clear(content);
      add(content, "p", "meta", error.message || "代码收集或读取未完成，请稍后重试。");
    }).then(function () {
      if (!current()) return;
      localButton.disabled = false; collectButton.disabled = false;
    });
  }
  localButton.addEventListener("click", function () { request(false); });
  collectButton.addEventListener("click", function () { request(true); });
  if (initialReport) draw(initialReport);
  else add(content, "p", "meta", "尚未读取代码审查记录；查看本地记录不会连接代码仓库。");
}

function renderDetail(item) {
  var panel = $("enrich-detail");
  clear(panel);
  add(panel, "h2", "", item.cve_id);
  add(panel, "p", "desc", item.description || "");
  var fields = add(panel, "div", "fields");
  [
    ["来源", itemSourceLabels(item).join("、")],
    ["产品", missingText(item.product, "未写明")],
    ["受影响版本", (item.affected || []).length ? (item.affected || []).join("、") : "未写明"],
    ["CVSS", scoreText(item.cvss) + (item.severity ? " · " + item.severity : "")],
    ["CVSS 版本", missingText(item.cvss_version, "未写明")],
    ["EPSS", epssText(item.epss)],
    ["CISA KEV", kevText(item.kev)],
    ["公开利用链接", item.poc_count ? item.poc_count + " 条链接" : "未见 Exploit 标记"],
    ["论文", item.paper_count ? item.paper_count + " 篇" : "尚未关联"],
    ["记录类型", isDemoItem(item) ? "演示数据" : "联网/入库情报"]
  ].forEach(function (pair) {
    var field = add(fields, "div", "field");
    add(field, "span", "", pair[0]);
    add(field, "b", "", pair[1]);
  });
  renderAssessment(panel, item.assessment);
  renderGuidance(panel, item.related_guidance);
  renderArticleCandidates(panel, item.cve_id);
  renderPocCode(panel, item.cve_id, item.poc_code);
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
  var assetButton = add(panel, "button", "ghost", "评估影响资产（富集）");
  assetButton.type = "button";
  assetButton.addEventListener("click", function () {
    var drawer = $("asset-drawer");
    if (drawer) drawer.open = true;
    loadAssets(item.cve_id).then(function () { return evaluateSavedAssets(); }).catch(showError);
    if ($("asset-cve")) $("asset-cve").value = item.cve_id;
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
  fetchButton.disabled = offlineDemo;
  if (offlineDemo) fetchButton.textContent = "离线演示使用已加载的样例证据";
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
    if (offlineDemo) return;
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
  var declared = Promise.all([api("/api/assets"), api("/api/items")]).then(function (data) {
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
  return Promise.all([declared, loadAssetObservations()]);
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

var assetImpactRequestVersions = {declared: 0, observations: 0};

function assetImpactFormKey(kind) {
  if (kind === "declared") return $("asset-json").value;
  return JSON.stringify([$("asset-observation-provider").value, $("asset-observation-json").value,
    $("asset-observation-fields").value, !!$("asset-observation-is-demo").checked]);
}

function beginAssetImpactRequest(kind, useForm) {
  return {kind: kind, version: ++assetImpactRequestVersions[kind], cve: $("asset-cve").value,
    form: useForm ? assetImpactFormKey(kind) : null};
}

function isCurrentAssetImpactRequest(context) {
  return context.version === assetImpactRequestVersions[context.kind]
    && context.cve === $("asset-cve").value
    && (context.form === null || context.form === assetImpactFormKey(context.kind));
}

function renderAssetImpact(report, target) {
  target = target || $("asset-impact");
  clear(target);
  var observations = report.inventory_source === "provider_export";
  add(target, "p", "title", report.cve_id + " · " + (report.preview ? "输入内容预览，尚未保存" : observations ? "已保存平台观测评估" : "已保存清单评估"));
  add(target, "p", "desc", "版本命中 " + report.counts.matched_version + " · 待确认 " + report.counts.unknown + " · 未命中当前范围 " + report.counts.not_matched + "；" + (observations ? "演示观测 " : "演示资产 ") + report.demo_count + " 条");
  if (!report.asset_count) add(target, "p", "empty", observations ? "暂无平台观测，无法评估具体组件。" : "尚未登记资产，无法评估具体组件。");
  (report.results || []).forEach(function (result) {
    var asset = result.asset, block = add(target, "div", "asset-card " + result.status);
    add(block, "b", "", asset.name + " · " + result.label + (asset.is_demo ? "（演示资产）" : ""));
    add(block, "p", "desc", asset.asset_id + " · " + inventorySummary(asset));
    add(block, "p", "desc", result.reason + "；" + result.priority);
    if (result.provider_observation) {
      var observation = result.provider_observation;
      add(block, "p", "meta", "平台观测：" + observation.provider + " · " + (observation.observed_at || "时间未知") + " · " + (observationTimeLabels[observation.time_status] || observation.time_status));
      add(block, "p", "meta", "产品判定：" + (observationIdentityLabels[observation.identity_status] || observation.identity_status));
      add(block, "p", "meta", "导入文本 SHA-256：" + (observation.source_response_sha256 || "未知") + " · 记录位置：" + (observation.locator || "未知"));
    }
    var activeChecks = (result.checks || []).filter(function (row) { return row.status === result.status; });
    activeChecks.forEach(function (row) { add(block, "p", "meta", "来源范围：" + row.range + " · " + row.pointer); });
    (result.evidence_ids || []).forEach(function (id) {
      var evidence = (report.evidence || []).find(function (row) { return row.citation_id === id; });
      if (!evidence) return;
      var isObservationEvidence = (result.observation_evidence_ids || []).indexOf(id) >= 0;
      var label = (isObservationEvidence ? "观测证据：" : "范围证据：") + id;
      if (typeof evidence.url === "string" && (/^https?:\/\//i.test(evidence.url) || /^\/(?!\/)/.test(evidence.url))) {
        var link = add(block, "a", "meta", label);
        link.href = evidence.url; link.target = "_blank"; link.rel = "noopener";
      } else add(block, "p", "meta", label);
    });
  });
  (report.limitations || []).concat(report.warnings || []).forEach(function (text) { add(target, "p", "meta", text); });
  if (report.source) add(target, "p", "meta", "漏洞范围快照获取于 " + dateText(report.source.retrieved_at));
}

function evaluateSavedAssets() {
  try {
    var cve = selectedAssetCve(), context = beginAssetImpactRequest("declared", false);
    return api("/api/asset-impact/" + encodeURIComponent(cve)).then(function (report) {
      if (isCurrentAssetImpactRequest(context) && report.cve_id === cve) renderAssetImpact(report);
    });
  }
  catch (error) { showError(error); return Promise.resolve(); }
}

on("asset-demo", "click", function () {
  api("/api/assets/demo").then(function (data) {
    assetImpactRequestVersions.declared += 1;
    assetImpactRequestVersions.observations += 1;
    $("asset-json").value = JSON.stringify(data, null, 2);
    $("asset-message").textContent = "已填入 3 条虚构演示资产，尚未保存。选择 CVE-2024-37032 后可预览。";
    $("asset-cve").value = "CVE-2024-37032";
  }).catch(showError);
});
on("asset-file", "change", function () {
  var file = this.files[0];
  if (!file) return;
  if (file.size > 1024 * 1024) { showError(new Error("JSON 文件不能超过 1 MB。")); return; }
  file.text().then(function (text) { assetImpactRequestVersions.declared += 1; $("asset-json").value = text.replace(/^\uFEFF/, ""); $("asset-message").textContent = "已读取文件，尚未保存；请先预览核对。"; }).catch(showError);
});
on("asset-preview", "click", function () {
  clearError();
  var button = $("asset-preview");
  try {
    var payload = assetPayload();
    payload.cve_id = selectedAssetCve();
    var context = beginAssetImpactRequest("declared", true);
    button.disabled = true;
    api("/api/assets/preview", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}).then(function (report) {
      if (isCurrentAssetImpactRequest(context) && report.cve_id === context.cve) renderAssetImpact(report);
    }).catch(showError).then(function () { button.disabled = false; });
  } catch (error) { showError(error); }
});
on("asset-save", "click", function () {
  clearError();
  var button = $("asset-save");
  try {
    var payload = assetPayload();
    assetImpactRequestVersions.declared += 1;
    button.disabled = true;
    api("/api/assets/import", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}).then(function (data) {
      assetImpactRequestVersions.declared += 1;
      $("asset-message").textContent = "已保存：新增 " + data.created + " 条，更新 " + data.updated + " 条；其他已登记资产保留。";
      clear($("asset-impact"));
      add($("asset-impact"), "p", "empty", "清单已更新，已安排 " + (data.investigations_queued || 0) + " 项相关研判；请在资产风险页面查看进度与结论。");
      return loadAssets();
    }).catch(showError).then(function () { button.disabled = false; });
  } catch (error) { showError(error); }
});
on("asset-evaluate", "click", function () { clearError(); evaluateSavedAssets().catch(showError); });
on("asset-cve", "change", function () {
  assetImpactRequestVersions.declared += 1;
  assetImpactRequestVersions.observations += 1;
  ["asset-impact", "asset-observation-impact"].forEach(function (id) {
    clear($(id)); add($(id), "p", "empty", "情报已切换，请重新预览或评估。");
  });
});
on("asset-json", "input", function () {
  assetImpactRequestVersions.declared += 1;
  clear($("asset-impact")); add($("asset-impact"), "p", "empty", "输入已修改，请重新预览或评估。");
});

var observationIdentityLabels = {exact_cpe: "明确 CPE 标识", exact_alias: "明确产品字段的固定映射", conflict: "产品身份或版本冲突，需核查", confirmed: "产品标识已解析", known: "产品标识已解析", explicit: "明确产品标识", unknown: "产品标识未知", ambiguous: "产品标识待确认"};
var observationTimeLabels = {current: "观测时间有效", recent: "近期观测", valid: "观测时间有效", stale: "历史观测，可能已过时", unknown: "观测时间未知", invalid: "观测时间无效", future: "观测时间在未来，需核对"};

function renderAssetObservationItems(target, items) {
  clear(target);
  if (!items || !items.length) add(target, "p", "empty", "暂无平台观测。空结果不代表互联网中没有受影响资产。");
  (items || []).forEach(function (item) {
    var block = add(target, "div", "asset-card");
    var address = item.address || "地址未知";
    if (address.indexOf(":") >= 0 && address[0] !== "[") address = "[" + address + "]";
    add(block, "b", "", (item.provider || "来源未知") + " · " + address + (item.port != null ? ":" + item.port : "") + (item.is_demo ? "（虚构演示观测）" : ""));
    add(block, "p", "desc", "产品：" + (item.product || "未知") + " · 版本：" + (item.version || "未知，不能判定受影响"));
    add(block, "p", "meta", "平台观测时间：" + (item.observed_at || "未知") + " · " + (observationTimeLabels[item.time_status] || item.time_status || "观测时间未知"));
    add(block, "p", "meta", "产品判定：" + (observationIdentityLabels[item.identity_status] || item.identity_status || "产品标识未知"));
    add(block, "p", "meta", "导入文本 SHA-256：" + (item.source_response_sha256 || "未知") + " · 记录位置：" + (item.locator || "未知"));
    (item.warnings || []).forEach(function (warning) { add(block, "p", "meta", warning); });
  });
}

function loadAssetObservations() {
  return api("/api/asset-observations").then(function (data) {
    $("asset-observation-count").textContent = data.count + " 条，其中演示观测 " + data.demo_count + " 条";
    renderAssetObservationItems($("asset-observation-list"), data.items);
  }).catch(function (error) {
    $("asset-observation-count").textContent = "读取失败";
    clear($("asset-observation-list"));
    add($("asset-observation-list"), "p", "empty", "观测读取失败，未显示上次列表。请稍后重试：" + error.message);
    showError(error);
  });
}

function assetObservationPayload() {
  var content = $("asset-observation-json").value.replace(/^\uFEFF/, "");
  if (!content.trim()) throw new Error("请先读取平台导出文件或填入演示结果。");
  if (new TextEncoder().encode(content).length > 1024 * 1024) throw new Error("平台结果不能超过 1 MiB。");
  try { JSON.parse(content); }
  catch (error) {
    try { content.split(/\r?\n/).filter(function (line) { return line.trim(); }).forEach(function (line) { JSON.parse(line); }); }
    catch (lineError) { throw new Error("平台结果须为有效的 JSON 或每行一条 JSON 的 JSONL；请检查原导出内容。"); }
  }
  var fieldText = $("asset-observation-fields").value.trim();
  var fields = fieldText ? fieldText.split(",").map(function (field) { return field.trim(); }) : [];
  if (fields.some(function (field) { return !field; })) throw new Error("列名中有空项，请按实际导出顺序填写，或留空。");
  return {provider: $("asset-observation-provider").value, content: content, fields: fields, is_demo: !!$("asset-observation-is-demo").checked};
}

function renderAssetObservationPreview(data) {
  renderAssetObservationItems($("asset-observation-preview-list"), data.items);
  var target = $("asset-observation-preview-list");
  add(target, "p", "meta", "本次 " + data.count + " 条 · " + data.provider + (data.is_demo ? " · 演示结果" : "") + "；尚未保存。");
  add(target, "p", "meta", "导入文本 SHA-256：" + (data.source_response_sha256 || "未知"));
  (data.warnings || []).forEach(function (warning) { add(target, "p", "meta", warning); });
  if (data.impact) renderAssetImpact(data.impact, $("asset-observation-impact"));
  else {
    clear($("asset-observation-impact"));
    add($("asset-observation-impact"), "p", "empty", "此次仅预览观测；选择上方 CVE 后重新预览，可评估版本影响。");
  }
  $("asset-observation-message").textContent = "已预览 " + data.count + " 条观测，尚未保存。产品、版本和观测时间请按原始来源核对。";
}

on("asset-observation-demo", "click", function () {
  var button = $("asset-observation-demo");
  button.disabled = true;
  clearError();
  api("/api/asset-observations/demo").then(function (data) {
    assetImpactRequestVersions.observations += 1;
    $("asset-observation-provider").value = data.provider;
    $("asset-observation-json").value = data.content;
    $("asset-observation-fields").value = (data.fields || []).join(",");
    $("asset-observation-is-demo").checked = !!data.is_demo;
    $("asset-observation-message").textContent = "已填入虚构平台观测，尚未保存。先预览可检查解析结果。";
    clear($("asset-observation-preview-list"));
    clear($("asset-observation-impact"));
  }).catch(showError).then(function () { button.disabled = false; });
});

on("asset-observation-file", "change", function () {
  var file = this.files[0];
  if (!file) return;
  if (file.size > 1024 * 1024) { showError(new Error("平台结果文件不能超过 1 MiB。")); return; }
  file.text().then(function (text) {
    assetImpactRequestVersions.observations += 1;
    $("asset-observation-json").value = text.replace(/^\uFEFF/, "");
    $("asset-observation-message").textContent = "已读取平台结果，尚未保存；请核对来源、列名与演示标记，再预览。";
    clear($("asset-observation-preview-list"));
    clear($("asset-observation-impact"));
  }).catch(showError);
});

on("asset-observation-preview", "click", function () {
  var button = $("asset-observation-preview");
  clearError();
  try {
    var payload = assetObservationPayload();
    if ($("asset-cve").value) payload.cve_id = $("asset-cve").value;
    var context = beginAssetImpactRequest("observations", true);
    button.disabled = true;
    api("/api/asset-observations/preview", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}).then(function (data) {
      if (isCurrentAssetImpactRequest(context) && (!data.impact || data.impact.cve_id === context.cve)) renderAssetObservationPreview(data);
    }).catch(showError).then(function () { button.disabled = false; });
  } catch (error) { button.disabled = false; showError(error); }
});

on("asset-observation-save", "click", function () {
  var button = $("asset-observation-save");
  clearError();
  try {
    var payload = assetObservationPayload();
    assetImpactRequestVersions.observations += 1;
    button.disabled = true;
    api("/api/asset-observations/import", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}).then(function (data) {
      assetImpactRequestVersions.observations += 1;
      var summary = "观测已保存：新增 " + data.created + " 条，更新 " + data.updated + " 条";
      if (data.unchanged != null) summary += "，已存在 " + data.unchanged + " 条";
      $("asset-observation-message").textContent = summary + "。其他观测和自行登记清单保留。";
      clear($("asset-observation-preview-list"));
      clear($("asset-observation-impact"));
      add($("asset-observation-preview-list"), "p", "empty", "输入结果已保存，请核对右侧已保存观测。修改输入后可重新预览。");
      add($("asset-observation-impact"), "p", "empty", "观测已更新，请重新评估。平台观测不等于漏洞复现结果。");
      return loadAssetObservations();
    }).catch(showError).then(function () { button.disabled = false; });
  } catch (error) { button.disabled = false; showError(error); }
});

on("asset-observation-evaluate", "click", function () {
  var button = $("asset-observation-evaluate");
  clearError();
  try {
    var cve = selectedAssetCve();
    var context = beginAssetImpactRequest("observations", false);
    button.disabled = true;
    api("/api/asset-observation-impact/" + encodeURIComponent(cve)).then(function (data) {
      if (isCurrentAssetImpactRequest(context) && data.cve_id === cve) renderAssetImpact(data, $("asset-observation-impact"));
    }).catch(showError).then(function () { button.disabled = false; });
  } catch (error) { button.disabled = false; showError(error); }
});

function observationFormChanged() {
  assetImpactRequestVersions.observations += 1;
  clear($("asset-observation-preview-list"));
  clear($("asset-observation-impact"));
  add($("asset-observation-preview-list"), "p", "empty", "输入已修改，请重新预览。");
  add($("asset-observation-impact"), "p", "empty", "输入已修改，请重新预览或评估。");
}
on("asset-observation-provider", "change", observationFormChanged);
on("asset-observation-json", "input", observationFormChanged);
on("asset-observation-fields", "input", observationFormChanged);
on("asset-observation-is-demo", "change", observationFormChanged);

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

on("sample-btn", "click", function () {
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

document.querySelectorAll(".pipeline button").forEach(function (button) {
  button.addEventListener("click", function () {
    setView(button.getAttribute("data-view"));
  });
});

document.querySelectorAll("#arch-stack [data-go]").forEach(function (node) {
  node.addEventListener("click", function () {
    setView(node.getAttribute("data-go"));
  });
  node.addEventListener("keydown", function (event) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      setView(node.getAttribute("data-go"));
    }
  });
  if (!node.getAttribute("tabindex")) node.setAttribute("tabindex", "0");
  if (!node.getAttribute("role")) node.setAttribute("role", "button");
});

on("goto-monitor", "click", function () { setView("monitor"); });
on("keyword", "input", function () {
  monitorKeyword();
  loadItems("monitor");
});
on("filter", "input", function () { loadItems("monitor"); });
on("clear-keyword-btn", "click", function () {
  if ($("keyword")) $("keyword").value = "";
  if ($("filter")) $("filter").value = "";
  clearError();
  setMonitorStatus("已清除关键词，正在显示全部情报流。");
  loadItems("monitor");
});

function diagnoseEmptyFeed(runData, feed, keyword) {
  var bits = [];
  var diag = (runData && runData.source_diag) || {};
  var team = (runData && runData.team) || {};
  var teamDocs = (feed && feed.team_documents) || {};
  var scope = monitorScope || "all";

  function srcLine(label, row) {
    if (!row) return;
    var st = row.status || "未知";
    bits.push(label + ":" + st);
  }
  srcLine("NVD", diag.nvd);
  srcLine("OSV", diag.osv);
  srcLine("多源情报", diag.b_team || (team.enabled === false ? {status: "已禁用"} : team.reachable === false ? { status: "不可达" } : null));
  srcLine("多源情报刷新", diag.b_monitor);
  srcLine("资料同步", diag.c_library_sync);

  var rs = (runData && runData.round_stats) || {};
  bits.push(collectionSummaryText(runData && runData.collection_summary));
  if ((diag.written === 0 || (runData && runData.count === 0)) && (rs.inserted === 0 || rs.inserted == null)) {
    bits.push("本轮AI情报新增 0"
      + (rs.hit != null
        ? "（查询返回 " + rs.hit + "，水位后保留 " + (rs.kept || 0) + "，合并 " + (rs.merged || 0) + "）"
        : ""));
  }
  if (rs.hit > 0 && (rs.inserted || 0) === 0) {
    bits.push("本轮无新增AI情报编号；不代表各来源没有新增记录，已有情报仍可浏览");
  }
  if (team.enabled !== false && team.reachable === false) {
    bits.push("部分来源暂不可用，仍可查看 NVD / OSV 与已有资料");
  }
  if (teamDocs.enabled !== false && teamDocs.reachable === false) {
    bits.push("资料摘要暂不可读" + (teamDocs.error ? "（" + teamDocs.error + "）" : ""));
  }
  if (keyword) {
    bits.push("当前关键词「" + keyword + "」可能过窄—可清除");
  }
  if (scope && scope !== "all") {
    bits.push("类型筛选=" + scope + "（可切回全部）");
  }
  if (monitorCategoryFilter && monitorCategoryFilter !== "all") {
    bits.push("分类筛选=" + monitorCategoryFilter);
  }
  if (monitorSourceFilter && monitorSourceFilter !== "all") {
    bits.push("来源筛选=" + monitorSourceFilter);
  }
  if (!bits.length) {
    bits.push("可再点「立即刷新一轮」，或稍后再试");
  }
  return bits.join("；");
}

function stopMonitorProgressTimers() {
  if (monitorElapsedTimer) {
    clearInterval(monitorElapsedTimer);
    monitorElapsedTimer = null;
  }
  if (monitorPollTimer) {
    clearInterval(monitorPollTimer);
    monitorPollTimer = null;
  }
}

function startMonitorProgressTimers(busyBase) {
  stopMonitorProgressTimers();
  monitorRefreshStartedAt = Date.now();
  lastMonitorToastPhase = "";
  var lastPhaseSeen = "";
  var tick = function () {
    var sec = Math.max(0, Math.round((Date.now() - monitorRefreshStartedAt) / 1000));
    var phase = (lastMonitorStatus && lastMonitorStatus.run_phase) || lastPhaseSeen || "监测刷新中";
    // Status line ticks every second; toast stays quiet so it does not fight phase updates.
    setMonitorStatus(busyBase + "已等待 " + sec + " 秒…");
    renderMonitorLive(lastMonitorStatus, {
      running: true,
      elapsedSec: sec,
      phase: phase,
    });
  };
  tick();
  monitorElapsedTimer = setInterval(tick, 1000);
  monitorPollTimer = setInterval(function () {
    api("/api/monitor/status?light=1").then(function (data) {
      if (!monitorRefreshing) return;
      lastMonitorStatus = data;
      var sec = Math.max(0, Math.round((Date.now() - monitorRefreshStartedAt) / 1000));
      var phase = data.run_phase || "监测执行中";
      renderMonitorLive(data, {
        running: true,
        elapsedSec: sec,
        phase: phase,
      });
      // Toast only when the product stage changes — not every poll.
      if (phase && phase !== lastMonitorToastPhase) {
        lastMonitorToastPhase = phase;
        lastPhaseSeen = phase;
        showToast("监测进行中：" + phase + "（已 " + sec + " 秒）", "busy");
      }
    }).catch(function () {});
  }, 1500);
}

function runMonitorRefresh(options) {
  options = options || {};
  var button = $("auto-monitor-btn");
  var overviewBtn = $("overview-monitor-btn");
  var keyword = monitorKeyword();
  var syncLibrary = options.sync_library !== false;
  if (!button && !overviewBtn) {
    showToast("找不到刷新按钮，请刷新页面后重试", "error");
    return Promise.reject(new Error("monitor button missing"));
  }
  if (monitorRefreshing) {
    showToast("已有一轮监测在进行，请稍候…", "busy");
    return Promise.resolve(null);
  }
  monitorRefreshing = true;
  setBusyButton(button, true, "正在刷新…", "立即刷新一轮");
  setBusyButton(overviewBtn, true, "正在刷新…", "立即刷新监测");
  clearError();
  // Keep pipeline shell visible immediately so layout does not jump when first poll arrives.
  // Also seed lastMonitorStatus so the 1s tick cannot re-paint a stale all-zero done pipeline.
  var startPipe = {
    status: "running",
    elapsed_sec: 0,
    metrics: {},
    stages: [
      { id: "monitoring", title: "监测中", subtitle: "同步多源已分类情报及变更", status: "running", did: "多方面来源一并抓取中…" },
      { id: "persist", title: "整理入库", subtitle: "规范化并合并写入知识库", status: "pending" },
      { id: "library_sync", title: "资料同步", subtitle: "公开与资料摘要（可选）", status: "pending" }
    ]
  };
  lastMonitorStatus = lastMonitorStatus ? {
    last_run: lastMonitorStatus.last_run,
    last_count: lastMonitorStatus.last_count,
    next_run: lastMonitorStatus.next_run,
    interval_minutes: lastMonitorStatus.interval_minutes,
    interval_hours: lastMonitorStatus.interval_hours,
    auto_enabled: lastMonitorStatus.auto_enabled,
    offline_demo: lastMonitorStatus.offline_demo,
    team: lastMonitorStatus.team,
    running: true,
    run_phase: "监测刷新中",
    pipeline: startPipe
  } : { running: true, run_phase: "监测刷新中", pipeline: startPipe };
  renderCollectPipeline(startPipe, { forceShow: true });
  renderMonitorLive(lastMonitorStatus, { running: true, elapsedSec: 0, phase: "监测刷新中", pipeline: startPipe });
  var busyBase = keyword
    ? ("正在按「" + keyword + "」监测刷新，")
    : "监测刷新中（可能需数十秒），";
  showToast("监测已开始：监测中 → 整理入库 → 资料同步", "busy");
  startMonitorProgressTimers(busyBase);
  return api("/api/monitor/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ keyword: keyword, sync_library: syncLibrary, max_documents: 30 })
  }).then(function (data) {
    setTeamHealth(data.team);
    var lib = data.library_sync || {};
    var warns = data.warnings || [];
    var bmon = (data.source_diag && data.source_diag.b_monitor) || {};
    var rs = data.round_stats || {};
    var outcomeLabel = {success: "采集成功", partial: "采集部分成功", failed: "采集失败"}[data.status] || "本轮完成";
    // Stop progress timers before painting the final pipeline so busy/result copy do not race.
    stopMonitorProgressTimers();
    if (data.pipeline) renderCollectPipeline(data.pipeline, { forceShow: true });
    renderCollectionSummary(data.collection_summary);
    var roundLine = "AI情报新增 " + monitorCount(data.count != null ? data.count : rs.inserted)
      + " · AI同步返回 " + monitorCount(rs.hit)
      + " · AI同步水位后保留 " + monitorCount(rs.kept)
      + " · AI情报合并 " + monitorCount(rs.merged)
      + "；" + collectionSummaryText(data.collection_summary);
    setMonitorStatus(outcomeLabel + "：" + roundLine
      + (bmon.status ? "；多源情报刷新 " + bmon.status : "")
      + (lib && lib.status ? "；资料同步 " + lib.status : "")
      + "。正在更新情报流…");
    // One intermediate toast only — final ok/error toast after feed settles.
    showToast(outcomeLabel + "：" + roundLine + "，正在更新情报流…", "busy");
    return loadItems("monitor").then(function (feed) {
      var total = ((feed && feed.counts) || {}).total || ((feed && feed.items) || []).length || 0;
      var done = outcomeLabel + "：" + roundLine + "；当前显示 "
        + total + " 条" + (keyword ? "（关键词「" + keyword + "」）" : "")
        + "。";
      if ((data.count || 0) === 0 && (rs.hit || 0) > 0) {
        done += " 本轮无新增AI情报编号；来源可能已新增非AI记录、更新已有记录，或有来源尚未完成，请对照来源结果。";
      }
      if (data.status === "failed") done += " 采集未成功，当前显示保留的已有记录。";
      setMonitorStatus(done);
      var toastKind = (warns.length || data.status === "failed" || data.status === "partial") ? "error" : (((data.count || 0) === 0 && total === 0) ? "error" : "ok");
      showToast(done + (warns.length ? " " + warns[0] : ""), toastKind);
      if (!total) {
        var why = diagnoseEmptyFeed(data, feed, keyword);
        showError(new Error(data.status === "failed"
          ? "采集失败，暂无已保存的匹配条目。" + (data.error || "") + why
          : (keyword ? "刷新已完成，但关键词「" + keyword + "」没有匹配条目。" + why
                     : "刷新已完成，但情报流仍为空。" + why)));
      } else if ((data.count || 0) === 0 && (rs.hit || 0) > 0) {
        // Visible work, empty keep — not an error, but surface explanation.
        clearError();
      }
      return data;
    });
  }).catch(function (error) {
    showError(error);
    setMonitorStatus("刷新失败：" + (error.message || "请求失败") + " — 可重试");
    showToast("刷新失败：" + (error.message || "请求失败"), "error");
    throw error;
  }).then(function (data) {
    stopMonitorProgressTimers();
    monitorRefreshing = false;
    lastMonitorToastPhase = "";
    setBusyButton(button, false, null, "立即刷新一轮");
    setBusyButton(overviewBtn, false, null, "立即刷新监测");
    return loadMonitorStatus().then(function () {
      if ($("overview") && !$("overview").hidden) loadOverview();
      return data;
    });
  }, function (error) {
    stopMonitorProgressTimers();
    monitorRefreshing = false;
    lastMonitorToastPhase = "";
    setBusyButton(button, false, null, "立即刷新一轮");
    setBusyButton(overviewBtn, false, null, "立即刷新监测");
    loadMonitorStatus();
    throw error;
  });
}

on("collect-form", "submit", function (event) {
  event.preventDefault();
  var button = $("collect-btn");
  if (button) {
    button.disabled = true;
    button.textContent = "正在按关键词补采…";
  }
  clearError();
  var keyword = monitorKeyword();
  if (!keyword) {
    setMonitorStatus("未填关键词：默认已是自动宽范围监测；点「立即刷新一轮」即可，或先填写关键词再补采。");
    showToast("未填关键词 — 请用「立即刷新一轮」做自动宽范围刷新", "busy");
    if (button) {
      button.disabled = false;
      button.textContent = "按关键词补采 CVE";
    }
    loadItems("monitor");
    return;
  }
  setMonitorStatus("正在按「" + keyword + "」补采 CVE…");
  showToast("正在按「" + keyword + "」补采 CVE…", "busy");
  api("/api/collect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ keyword: keyword })
  }).then(function (data) {
    var resultLabel = {success: "补采成功", partial: "补采部分成功", failed: "补采失败"}[data.status] || "补采完成";
    var inserted = ((data.round_stats || {}).inserted) || 0;
    setMonitorStatus(resultLabel + "：本轮AI情报新增 " + inserted + " 条 CVE；正在刷新情报流…");
    return loadItems("monitor").then(function (feed) {
      var total = ((feed && feed.counts) || {}).total || ((feed && feed.items) || []).length || 0;
      var msg = resultLabel + "：本轮AI情报新增 " + inserted + " 条；当前流匹配「" + keyword + "」共 " + total + " 条。";
      setMonitorStatus(msg);
      showToast(msg, total && ["failed", "partial"].indexOf(data.status) === -1 ? "ok" : "error");
      if (!total) showError(new Error("补采已执行，但关键词「" + keyword + "」在情报流中暂无匹配。可清除关键词查看全部。"));
    });
  }).catch(function (error) {
    showError(error);
    setMonitorStatus("补采失败：" + (error.message || "请求失败"));
  }).then(function () {
    if (button) {
      button.disabled = false;
      button.textContent = "按关键词补采 CVE";
    }
  });
});

function bindClick(id, handler) {
  var el = $(id);
  if (!el) {
    console.warn("missing control", id);
    return;
  }
  el.addEventListener("click", function (event) {
    try {
      var result = handler(event);
      if (result && typeof result.catch === "function") {
        result.catch(function (error) {
          showError(error || new Error("操作失败"));
        });
      }
    } catch (error) {
      showError(error);
    }
  });
}

/* 委托兜底：即使个别控件缺失导致后续绑定中断，监测 CTA 仍可点 */
document.addEventListener("click", function (event) {
  var btn = event.target && event.target.closest
    ? event.target.closest("#auto-monitor-btn, #overview-monitor-btn")
    : null;
  if (!btn || btn.getAttribute("data-bound") === "1") return;
  event.preventDefault();
  try {
    if (btn.id === "overview-monitor-btn") setView("monitor", { skipFeed: true });
    var result = runMonitorRefresh({ sync_library: true });
    if (result && typeof result.catch === "function") {
      result.catch(function (error) { showError(error || new Error("操作失败")); });
    }
  } catch (error) {
    showError(error);
  }
});

bindClick("auto-monitor-btn", function () {
  return runMonitorRefresh({ sync_library: true });
});
bindClick("overview-monitor-btn", function () {
  setView("monitor", { skipFeed: true });
  return runMonitorRefresh({ sync_library: true });
});
["auto-monitor-btn", "overview-monitor-btn"].forEach(function (id) {
  var el = $(id);
  if (el) el.setAttribute("data-bound", "1");
});

document.addEventListener("click", function (event) {
  var scopeBtn = event.target && event.target.closest ? event.target.closest("[data-monitor-scope]") : null;
  if (scopeBtn) {
    event.preventDefault();
    setMonitorScope(scopeBtn.getAttribute("data-monitor-scope") || "all");
    return;
  }
  var catBtn = event.target && event.target.closest ? event.target.closest("[data-category-filter]") : null;
  if (catBtn) {
    event.preventDefault();
    setMonitorCategoryFilter(catBtn.getAttribute("data-category-filter") || "all");
    return;
  }
  var srcBtn = event.target && event.target.closest ? event.target.closest("[data-source-filter]") : null;
  if (srcBtn) {
    event.preventDefault();
    setMonitorSourceFilter(srcBtn.getAttribute("data-source-filter") || "all");
  }
});

bindClick("enrich-btn", function () {
  var button = $("enrich-btn");
  var status = $("enrich-status");
  setBusyButton(button, true, "正在查询…", "批量查询 EPSS / KEV / 论文");
  if (status) status.textContent = "正在查询 EPSS / KEV / 论文…";
  clearError();
  showToast("正在批量富集公开源（EPSS / KEV / 论文）…", "busy");
  return api("/api/enrich", { method: "POST" }).then(function (data) {
    return loadItems("enrich").then(function () {
      var docCount = Array.isArray(data && data.documents)
        ? data.documents.length
        : (typeof (data && data.documents) === "number" ? data.documents : 0);
      var msg = "富集完成"
        + (data && data.items != null ? "：处理 " + data.items + " 条" : "")
        + (docCount ? "，关联资料 " + docCount + " 条" : "（本轮无新增关联资料）")
        + "。";
      if (status) status.textContent = msg;
      showToast(msg, "ok");
      setBusyButton(button, false, null, "批量查询 EPSS / KEV / 论文");
    });
  }).catch(function (error) {
    if (status) status.textContent = "富集失败：" + (error.message || "请求失败");
    showError(error);
    showToast("富集失败：" + (error.message || "请求失败"), "error");
    setBusyButton(button, false, null, "批量查询 EPSS / KEV / 论文");
    throw error;
  });
});

var promptBox = $("prompts");
if (promptBox) {
  prompts.forEach(function (text) {
    var button = add(promptBox, "button", "", text);
    button.type = "button";
    button.addEventListener("click", function () {
      $("question").value = text;
    });
  });
}

on("new-session", "click", function () {
  askSessionId = "";
  $("focus").value = "";
  $("question").value = "";
  ["answer", "evidence", "ask-steps"].forEach(function (id) { clear($(id)); });
  $("verdict").textContent = "";
  $("conversation-context").textContent = "已开始新会话，请先指定漏洞。会话在当前服务内保留，空闲两小时或重启后失效。";
  clearError();
});

on("ask-form", "submit", function (event) {
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

on("settings-form", "submit", function (event) {
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

on("test-llm", "click", function () {
  $("test-result").textContent = "正在测试…";
  api("/api/settings/test", { method: "POST" }).then(function (data) {
    $("test-result").textContent = data.reply || "连接成功";
  }).catch(function (error) {
    $("test-result").textContent = error.message;
  });
});

var libraryKinds = {vendor_advisory: "项目安全公告", vendor_guidance: "厂商安全文档", research_article: "安全研究文章", academic_paper: "论文", standard: "标准 / 风险框架", policy: "政策法规"};
var libraryScopes = {team_summary: "接口题名/描述，非原始全文", abstract: "仅摘要", article_body: "文章正文", advisory_fields: "公告正文及字段", full_text_html: "HTML 全文文字", full_text_pdf: "PDF 各页文字", policy_articles: "政策条文", catalog_only: "仅目录"};
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
  if (data.reasoning_mode === "reasoning") {
    var kinds = {finding: "证据事实", inference: "证据推断", conditional: "条件性结论"};
    (data.reasoning_claims || []).forEach(function (claim) {
      var block = add(target, "details", "relation-fact");
      add(block, "summary", "", kinds[claim.kind] || "结论依据");
      add(block, "p", "", claim.text);
      (claim.assumptions || []).forEach(function (value) { add(block, "p", "hint", "尚需确认：" + value); });
      (claim.supports || []).forEach(function (support) {
        add(block, "p", "", support.quote);
        add(block, "p", "meta", "引用：" + support.citation_id);
      });
    });
    if ((data.reasoning_trace || []).length) {
      var trace = add(target, "details", "relation-fact");
      add(trace, "summary", "", "查看检索与核验记录");
      data.reasoning_trace.forEach(function (step) {
        if (step.tool === "local_library_search") {
          add(trace, "p", "meta", "检索「" + step.query + "」：新增 " + step.new_evidence + " 条证据");
        } else if (step.status === "received") {
          add(trace, "p", "meta", "已收到分析或核验结果，结论仍须通过证据检查。");
        } else if (step.missing_document_ids) {
          add(trace, "p", "hint", "未找到可用证据的资料：" + step.missing_document_ids.join("、"));
        }
      });
    }
    return;
  }
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
on("candidate-refresh", "click", loadCandidates);
on("candidate-graph", "click", function () {
  var topic = $("candidate-topic").value;
  api("/api/library/relations/graph?topic=" + encodeURIComponent(topic)).then(function (data) {
    if (topic === $("candidate-topic").value) renderLibraryRelations(data);
  }).catch(showError);
});
on("candidate-topic", "change", function () { clear($("candidate-list")); loadCandidates(); });
on("candidate-generate", "click", function () {
  var button = $("candidate-generate"), topic = $("candidate-topic").value;
  var ids = topic === "article_relations" ? librarySelectedDocs.slice() : [];
  if (topic === "article_relations" && !ids.length) { $("candidate-status").textContent = "请先在下方资料列表勾选 1 至 4 份资料，再提取文章关系。"; return; }
  button.disabled = true;
  $("candidate-status").textContent = "正在提取候选，所有新候选均需审核…";
  api("/api/library/relations/candidates", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({topic: topic, document_ids: ids})}).then(function (data) { if (topic === $("candidate-topic").value) renderCandidates(data); }).catch(function (error) { if (topic === $("candidate-topic").value) $("candidate-status").textContent = "提取失败，请检查所选资料与来源状态。"; showError(error); }).then(function () { button.disabled = false; });
});

function renderLibrarySyncStatus(overview) {
  var sourcesEl = $("library-sources");
  if (!sourcesEl) return;
  clear(sourcesEl);
  var sources = overview.sources || [];
  var publicSources = sources.filter(function (s) { return (s.category || "") !== "team" && s.source_id !== "team_documents" && s.name !== "多源情报资料" && s.name !== "资料摘要"; });
  var multiSources = sources.filter(function (s) { return (s.category || "") === "team" || s.source_id === "team_documents" || s.name === "多源情报资料" || s.name === "资料摘要"; });

  function statusLabel(st) {
    if (st === "ok") return "正常";
    if (st === "partial") return "部分成功";
    if (st === "error") return "失败";
    return st || "未知";
  }
  function summarize(rows) {
    if (!rows.length) return { ok: 0, bad: 0, last: "" };
    var ok = 0, bad = 0, last = "";
    rows.forEach(function (s) {
      if (s.status === "ok") ok += 1;
      else bad += 1;
      if ((s.checked_at || "") > last) last = s.checked_at || "";
    });
    return { ok: ok, bad: bad, last: last };
  }
  var pub = summarize(publicSources);
  var multi = summarize(multiSources);
  var pubStatus = $("library-sync-public-status");
  var multiStatus = $("library-sync-multi-status");
  if (pubStatus) {
    pubStatus.textContent = publicSources.length
      ? ("最近公开同步：" + pub.ok + " 源正常" + (pub.bad ? "，" + pub.bad + " 源异常" : "") + (pub.last ? " · " + dateText(pub.last) : ""))
      : (offlineDemo ? "离线演示使用已加载的合成资料，不连接公开源。" : "尚未同步公开资料。");
  }
  if (multiStatus) {
    multiStatus.textContent = multiSources.length
      ? ("最近资料摘要：" + statusLabel(multiSources[0].status) + (multiSources[0].discovered != null ? " · 窗口 " + multiSources[0].discovered + " 份" : "") + (multiSources[0].checked_at ? " · " + dateText(multiSources[0].checked_at) : ""))
      : "尚未同步资料摘要。";
  }

  var line = add(sourcesEl, "p", "meta", "同步概览：公开源 " + pub.ok + "/" + Math.max(publicSources.length, 1) + " 正常"
    + (multiSources.length ? " · 资料摘要 " + statusLabel(multiSources[0].status) : " · 资料摘要未跑")
    + "。下方按类型分组浏览。");

  var detail = add(sourcesEl, "details", "library-status-detail");
  add(detail, "summary", "", "查看来源同步明细（" + sources.length + "）");
  publicSources.concat(multiSources).forEach(function (source) {
    var kind = ((source.category || "") === "team" || source.name === "多源情报资料") ? "资料摘要" : "公开";
    var text = "【" + kind + "】" + source.name + " · " + statusLabel(source.status)
      + (source.discovered != null ? " · 发现 " + source.discovered + " 份" : "")
      + (source.checked_at ? " · " + dateText(source.checked_at) : "");
    if (source.error) text += " · " + source.error;
    add(detail, "p", "meta", text);
    if (typeof source.remaining === "number" && source.remaining) {
      add(detail, "p", "hint", "本轮只处理最近窗口 " + source.discovered + " 份，另有 " + source.remaining + " 份未纳入。");
    }
  });

  var failedRows = overview.failed_documents || [];
  if (!failedRows.length) return;
  var failBox = add(sourcesEl, "details", "library-fail-detail");
  var moduleCount = 0;
  var realFails = [];
  failedRows.forEach(function (row) {
    var err = row.error || "";
    var isModule = row.collapsed || /collectors\.team_documents|No module named/.test(err) || err.indexOf("多源资料模块暂不可用") >= 0;
    if (isModule) { moduleCount += 1; return; }
    realFails.push(row);
  });
  add(failBox, "summary", "", "同步问题 " + (realFails.length + (moduleCount ? 1 : 0)) + " 条（已折叠，不影响已入库资料）");
  if (moduleCount) {
    add(failBox, "p", "hint", "资料摘要同步曾暂不可用；已保留上次成功入库的资料，可稍后重试「同步资料摘要」。");
  }
  realFails.slice(0, 12).forEach(function (row) {
    var block = add(failBox, "div", "meta");
    add(block, "p", "", (row.retained_previous ? "保留旧存档 · " : "未入库 · ") + (row.error || "未知错误"));
    if (row.url) libraryLink(block, row.url, "查看来源");
  });
  if (realFails.length > 12) {
    add(failBox, "p", "hint", "另有 " + (realFails.length - 12) + " 条未展开。");
  }
}

function loadLibrary() {
  return api("/api/library?document_type=" + encodeURIComponent($("library-type").value)).then(function (data) {
    var counts = data.overview.types;
    $("library-summary").textContent = "已收录 " + data.overview.documents + " 份资料、" + data.overview.chunks + " 段存档内容；标准 / 风险框架 " + (counts.standard || 0) + "、政策法规 " + (counts.policy || 0) + "。";
    renderLibrarySyncStatus(data.overview || {});
    var target = $("library-list"); clear(target);
    if (!data.items.length) {
      add(target, "p", "empty", "此类型尚未收录资料。");
      return;
    }
    var byType = {};
    data.items.forEach(function (doc) {
      var kind = doc.document_type || "other";
      (byType[kind] = byType[kind] || []).push(doc);
    });
    var typeKeys = Object.keys(byType);
    typeKeys.forEach(function (kind, idx) {
      var rows = byType[kind];
      var host = target;
      if (typeKeys.length > 1) {
        var group = add(target, "details", "list-group");
        group.open = idx === 0;
        add(group, "summary", "list-group-sum", (libraryKinds[kind] || kind) + " · " + rows.length + " 份");
        host = add(group, "div", "list-group-body");
      }
      var pageKey = "library-" + kind;
      if (listPages[pageKey] == null) listPages[pageKey] = 1;
      var meta = pageSlice(rows, pageKey, LIST_PAGE_SIZE);
      meta.items.forEach(function (doc) { renderLibraryDocRow(host, doc, data.items); });
      renderPager(host, pageKey, meta, loadLibrary);
    });
  }).catch(showError);
}

function renderLibraryDocRow(target, doc, allItems) {
  var block = add(target, "div", "evidence-chunk");
  var button = add(block, "button", "text-btn", doc.title);
  button.type = "button";
  button.addEventListener("click", function () {
    api("/api/library/" + encodeURIComponent(doc.document_id)).then(renderLibraryEvidence).catch(showError);
  });
  add(block, "p", "meta", libraryKinds[doc.document_type] + " · " + doc.publisher + " · " + dateText(doc.published_at));
  var discoveryLabels = {team_api: "资料存档", explicit_source_text: "显式获取来源原文", historical_seed: "历史起始资料", explicit_full_text: "显式获取全文", fixed_reference_monitor: "固定官方原文监测", subscription: "订阅发现"};
  add(block, "p", "meta", libraryScopes[doc.content_scope] + " · " + doc.chunk_count + " 段 · " + (discoveryLabels[doc.discovery] || doc.discovery) + (doc.retained_previous ? " · 刷新失败，保留旧快照" : ""));
  if (doc.version) add(block, "p", "meta", "版本：" + doc.version);
  if (doc.team_document_id) add(block, "p", "meta", "资料记录：" + doc.team_document_id + " · 更新于 " + dateText(doc.team_content_updated_at));
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
    var fullLabel = (allItems || []).some(function (r) { return r.parent_document_id === doc.document_id; }) ? "刷新论文全文" : "获取论文全文";
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
}

on("library-type", "change", function () {
  librarySelectedDocs = [];
  Object.keys(listPages).forEach(function (key) {
    if (key.indexOf("library-") === 0) listPages[key] = 1;
  });
  loadLibrary();
  clear($("library-evidence"));
  clear($("library-relations"));
  $("library-answer").textContent = "资料类型已切换，请重新选择资料并提问。";
});
on("library-mode", "change", function () { clear($("library-relations")); clear($("library-evidence")); $("library-answer").textContent = "回答方式已切换，请重新提问。"; });
on("library-example", "click", function () { $("library-mode").value = "excerpt"; clear($("library-relations")); clear($("library-evidence")); $("library-question").value = "管理暂行办法对训练数据有什么规定？适用范围是什么？"; $("library-answer").textContent = "已填入政策示例，请选择对应政策并提问。"; });
on("library-relations-example", "click", function () {
  $("library-mode").value = "relations"; $("library-type").value = ""; librarySelectedDocs = [];
  $("library-question").value = "比较论文和 NIST 对间接提示注入的机制解释、防护建议及局限。";
  clear($("library-relations")); clear($("library-evidence")); $("library-answer").textContent = "已填入关系示例，将使用已核对的论文全文与 NIST 框架。"; loadLibrary();
});
on("library-supply-example", "click", function () {
  $("library-mode").value = "relations"; $("library-type").value = ""; librarySelectedDocs = [];
  $("library-question").value = "比较 HF 和 NIST 对模型供应链的加载风险、防护建议与扫描局限。";
  clear($("library-relations")); clear($("library-evidence")); $("library-answer").textContent = "已填入供应链示例，将使用 HF 文档存档与 NIST 框架。"; loadLibrary();
});
on("library-ask-form", "submit", function (event) {
  event.preventDefault(); clearError();
  var button = $("library-ask"); button.disabled = true; button.textContent = "正在检索原文…";
  $("library-answer").textContent = "正在按资料证据处理…"; clear($("library-evidence")); clear($("library-relations"));
  var requestMode = $("library-mode").value;
  var requestBody = JSON.stringify({question: $("library-question").value.trim(), document_ids: librarySelectedDocs, document_type: $("library-type").value, mode: $("library-mode").value === "reasoning" ? "reasoning" : "excerpts"});
  api(requestMode === "relations" ? "/api/library/analyze" : "/api/library/ask", {method: "POST", headers: {"Content-Type": "application/json"}, body: requestBody}).then(function (result) {
    if (requestMode !== $("library-mode").value || requestBody !== JSON.stringify({question: $("library-question").value.trim(), document_ids: librarySelectedDocs, document_type: $("library-type").value, mode: $("library-mode").value === "reasoning" ? "reasoning" : "excerpts"})) { $("library-answer").textContent = "问题或选择已变化，请重新提问。"; return; }
    $("library-answer").textContent = result.answer;
    renderLibraryRelations(result);
    var rows = result.evidence || [];
    ((result.reviewed_quotes || {}).evidence || []).forEach(function (row) { if (!rows.some(function (r) { return r.citation_id === row.citation_id; })) rows.push(row); });
    renderLibraryEvidence({evidence: rows, notice: requestMode === "reasoning" ? "结论附带来源引文；缺少前提、来源冲突或核验失败会明确提示。" : requestMode === "relations" ? "限定综合与来源事实分开展示；原文可在此核对。" : result.used_model ? "模型挑选的原文已核对；不构成自由推理结论。" : "依据检索原文摘录。"});
  }).catch(showError).then(function () { button.disabled = false; button.textContent = "按证据回答"; });
});
on("library-search-form", "submit", function (event) {
  event.preventDefault(); clearError();
  api("/api/library/search?q=" + encodeURIComponent($("library-query").value.trim()) + "&document_type=" + encodeURIComponent($("library-type").value)).then(renderLibraryEvidence).catch(showError);
});
on("library-sync", "click", function () {
  var button = $("library-sync");
  var idle = "同步公开资料";
  setBusyButton(button, true, "正在同步…", idle);
  clearError();
  showToast("正在同步公开原文（订阅 + 固定官方）…", "busy");
  api("/api/library/sync", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({per_source: 3, include_seeds: true})}).then(function (data) {
    var msg = "公开原文同步完成：" + data.ok + "/" + data.attempted + " 份";
    showToast(msg, "ok");
    clear($("library-evidence"));
    clear($("library-relations"));
    $("library-answer").textContent = "资料已更新，请重新提问。";
    add($("library-evidence"), "p", "hint", "资料已更新，请重新选择资料或检索。");
    return loadLibrary();
  }).catch(function (error) {
    showError(error);
    showToast("公开原文同步失败：" + (error.message || "请求失败"), "error");
  }).then(function () { setBusyButton(button, false, null, idle); });
});

on("library-team-sync", "click", function () {
  var button = $("library-team-sync");
  var idle = "同步资料摘要";
  setBusyButton(button, true, "正在同步…", idle);
  clearError();
  showToast("正在同步资料摘要（题名/描述窗口）…", "busy");
  api("/api/library/team-sync", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({max_documents: 30})}).then(function (data) {
    if (data.status === "skipped" || data.enabled === false) {
      showToast("资料摘要同步按配置已跳过，已有资料和选择保留。", "busy");
      return;
    }
    var msg = data.status === "error"
      ? "资料摘要暂不可用，已有资料仍可使用"
      : ("资料摘要同步完成：" + data.ok + "/" + data.attempted + " 份");
    showToast(msg, data.status === "error" ? "error" : "ok");
    librarySelectedDocs = []; clear($("library-evidence")); clear($("library-relations"));
    $("library-answer").textContent = data.status === "error" ? "资料摘要暂不可用，已有资料可继续使用。" : "资料摘要已同步，请重新选择资料并提问。";
    return loadLibrary();
  }).catch(function (error) {
    showError(error);
    showToast("资料摘要同步失败：" + (error.message || "请求失败"), "error");
  }).then(function () { setBusyButton(button, false, null, idle); });
});

setView("overview");
// Surface automatic monitor health early (no keyword required).
loadMonitorStatus();
api("/api/monitor/status").then(function (data) {
  if (data) setOfflineMode(data.offline_demo);
  if (offlineDemo) {
    showToast("离线样例已加载；手动刷新只同步本地样例。", "ok");
  } else if (data && data.running) {
    showToast("后台正在自动监测一轮宽范围 AI 安全情报…", "busy");
  } else if (data && data.last_run) {
    var statusLabel = {success: "成功", partial: "部分成功", failed: "失败"}[data.last_status] || "已结束";
    showToast("最近一轮监测" + statusLabel + "：" + data.last_run + "，新增 " + (data.last_count || 0) + " 条",
      ["failed", "partial"].indexOf(data.last_status) !== -1 ? "error" : "ok");
  }
}).catch(function () {});
