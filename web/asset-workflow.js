/* Asset workflow additions; retain the existing inventory and risk pages. */
var overviewRiskVersion = 0;

function parseAssetInventoryFile(text) {
  var payload;
  try { payload = JSON.parse(text.replace(/^\uFEFF/, "")); }
  catch (error) { throw new Error("文件不是有效 JSON，请检查格式。"); }
  if (payload && Array.isArray(payload.assets)) return {payload: payload, notice: ""};
  if (!payload || payload.bomFormat !== "CycloneDX" || !Array.isArray(payload.components)) throw new Error("请提供 assets 清单或 CycloneDX JSON 组件列表。");
  var aliases = {ollama: ["ollama", "ollama"], transformers: ["huggingface", "transformers"]};
  var assets = [], skipped = [], frontier = payload.components.slice();
  if (frontier.length > 500) throw new Error("每次最多导入 500 个组件，请分批处理。");
  var visited = 0;
  while (frontier.length) {
    var component = frontier.shift();
    if (++visited > 500) throw new Error("每次最多导入 500 个组件（含子组件）。");
    if (!component || typeof component !== "object") throw new Error("CycloneDX 组件必须为对象。");
    if (Array.isArray(component.components)) frontier.push.apply(frontier, component.components);
    var identity, qualifiers = {}, part = "a", cpeVersion = "";
    if (typeof component.cpe === "string") {
      var cpe = component.cpe.split(":");
      if (cpe.length === 13 && cpe[0] === "cpe" && cpe[1] === "2.3" && /^[aoh]$/.test(cpe[2]) && /^[a-z0-9_.-]+$/i.test(cpe[3]) && /^[a-z0-9_.-]+$/i.test(cpe[4]) && !/[\\?]/.test(component.cpe)) {
        identity = [cpe[3].toLowerCase(), cpe[4].toLowerCase()]; part = cpe[2];
        cpeVersion = /^[*-]$/.test(cpe[5]) ? "" : cpe[5];
        ["update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other"].forEach(function (key, i) { if (cpe[i + 6] !== "*") qualifiers[key] = cpe[i + 6]; });
      }
    } else {
      var name = typeof component.name === "string" ? component.name.toLowerCase() : "";
      var purl = typeof component.purl === "string" ? component.purl.match(/^pkg:pypi\/(ollama|transformers)(?:@([^?#]+))?$/i) : null;
      identity = purl ? aliases[purl[1].toLowerCase()] : !component.purl ? aliases[name] : null;
      if (purl && purl[2]) cpeVersion = purl[2];
    }
    if (!identity || (component.version && cpeVersion && component.version !== cpeVersion)) { skipped.push(component.name || "未命名组件"); continue; }
    assets.push({asset_id: "sbom-" + String(component.name || identity[1]).replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 42) + "-" + visited,
      name: String(component.name || identity[1]).slice(0, 120), vendor: identity[0], product: identity[1],
      part: part, version: component.version || cpeVersion || "", qualifiers: qualifiers, is_demo: false});
  }
  if (!assets.length) throw new Error("未找到可明确映射的组件。请提供精确 CPE，或用表单填写厂商和产品。自动别名目前支持 Ollama、Transformers。");
  return {payload: {assets: assets}, notice: "CycloneDX 已转换 " + assets.length + " 条；" + skipped.length + " 条缺少可靠标识或版本冲突，未纳入。" + (skipped.length ? "请手动核对：" + skipped.slice(0, 8).join("、") : "")};
}

function loadOverviewRisks() {
  var target = $("overview-risk-list");
  if (!target) return Promise.resolve();
  var version = ++overviewRiskVersion;
  return api("/api/risks?actionable=true&limit=5").then(function (data) {
    if (version !== overviewRiskVersion) return;
    clear(target);
    if ($("overview-risk-count")) $("overview-risk-count").textContent = "待处置关联 " + data.total + " 条 · 含待确认项，非已证实漏洞利用";
    if (!data.items.length) add(target, "p", "hint", "暂无待办。可在资产风险页载入演示，或登记组件后评估。");
    (data.items || []).forEach(function (row) {
      var button = add(target, "button", "row", ""); button.type = "button";
      add(button, "span", "title", (row.asset.name || row.asset_id) + " · " + row.cve_id);
      add(button, "span", "meta", row.disposition_label);
      add(button, "span", "desc", row.label + " · " + row.priority + (row.asset.is_demo ? " · 演示资产" : ""));
      button.addEventListener("click", function () { setView("risks"); });
    });
    if (data.total > data.items.length) add(target, "p", "hint", "共 " + data.total + " 条待办，展示前 5 条。");
  }).catch(function () { if (version === overviewRiskVersion) { clear(target); add(target, "p", "hint", "待办暂不可读取，请到资产风险页刷新。"); } });
}

async function runAssetDemo(button) {
  var buttons = [$("asset-demo"), $("risk-demo")].filter(Boolean);
  if (buttons.some(function (node) { return node.disabled; })) return;
  var labels = buttons.map(function (node) { return node.textContent; });
  var riskResult = $("risk-demo-result"), report;
  function feedback(text) {
    [$("asset-message"), $("risk-demo-message")].filter(Boolean).forEach(function (node) {
      node.textContent = text;
      node.hidden = false;
    });
  }
  buttons.forEach(function (node) {
    node.disabled = true;
    node.textContent = "正在载入并评估…";
    node.setAttribute("aria-busy", "true");
  });
  if (riskResult) riskResult.hidden = true;
  clearError();
  feedback("正在保存演示组件并自动匹配已收录的相关漏洞；其他已登记资产保留。");
  try {
    report = await api("/api/assets/demo/match", {method: "POST"});
    assetImpactRequestVersions.declared += 1;
    $("asset-json").value = JSON.stringify({assets: report.demo_assets}, null, 2);
    clear($("asset-impact"));
    add($("asset-impact"), "p", "hint", "演示组件已载入。请打开资产风险，先选组件，再查看它关联的全部 CVE。");
    if (riskResult && $("risk-demo-impact")) {
      $("risk-demo-impact").textContent = "本次载入：" + report.demo_assets.map(function (asset) { return asset.name || asset.asset_id; }).join("、") + "。";
      riskResult.hidden = false;
    }
    var complete = "演示组件已载入：" + report.demo_assets.length + " 个组件，当前共有 " + report.risks_saved
      + " 条 CVE 关联。点击下方组件展开影响详情；后台会继续更新。重复载入会更新原记录，关联总数可能不变。";
    feedback(complete);
    if (button === $("asset-demo")) setView("risks");
    await loadAssets();
    if ($("risks") && !$("risks").hidden) await loadRisks();
    await loadOverviewRisks();
    feedback(complete);
    return report;
  } catch (error) {
    feedback((report ? "演示评估已保存，但刷新列表未完整完成；请点击“刷新结果”。" : "演示未能确认完成，请刷新清单与风险列表后查看。") + "原因：" + error.message);
    throw error;
  } finally {
    buttons.forEach(function (node, index) {
      node.disabled = false;
      node.textContent = labels[index];
      node.removeAttribute("aria-busy");
    });
  }
}

on("risk-demo", "click", function () { runAssetDemo($("risk-demo")).catch(showError); });
on("asset-open-risks", "click", function () { setView("risks"); });
on("overview-risk-open", "click", function () { setView("risks"); });
on("asset-sync", "click", async function () {
  var button = $("asset-sync");
  try {
    var cve = selectedAssetCve(), context = beginAssetImpactRequest("declared", false);
    button.disabled = true;
    var report = await api("/api/asset-impact/" + encodeURIComponent(cve) + "/save", {method: "POST"});
    if (isCurrentAssetImpactRequest(context)) {
      renderAssetImpact(report);
      $("asset-message").textContent = "已同步 " + report.risks_saved + " 条资产风险；可打开资产风险查看处置与依据。";
    }
    await loadOverviewRisks();
  } catch (error) { showError(error); }
  finally { button.disabled = false; }
});

on("asset-entry-component", "change", function () {
  var parts = this.value.split("/");
  if (parts.length === 2) { $("asset-entry-vendor").value = parts[0]; $("asset-entry-product").value = parts[1]; }
});
on("asset-observation-field-template", "click", function () {
  $("asset-observation-provider").value = "fofa";
  $("asset-observation-fields").value = "host,ip,port,product,product.version";
  $("asset-observation-message").textContent = "已填入示例列名，尚未保存。请按真实导出核对列名与顺序，再预览。";
  assetImpactRequestVersions.observations += 1;
});
on("asset-entry-form", "submit", function (event) {
  event.preventDefault(); clearError();
  try {
    var row = {asset_id: $("asset-entry-id").value.trim(), name: $("asset-entry-name").value.trim(),
      vendor: $("asset-entry-vendor").value.trim().toLowerCase(), product: $("asset-entry-product").value.trim().toLowerCase(),
      version: $("asset-entry-version").value.trim(), exposure: $("asset-entry-exposure").value,
      is_demo: !!$("asset-entry-demo").checked};
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(row.asset_id)) throw new Error("资产编号使用 1～64 位字母、数字、下划线、点或连字符。");
    if (!row.name) throw new Error("请填写资产名称。");
    if (!/^[a-z0-9_.-]+$/.test(row.vendor) || !/^[a-z0-9_.-]+$/.test(row.product)) throw new Error("厂商和产品请填写精确 CPE 标识，例如 ollama；不能填写中文或空格。");
    var payload = $("asset-json").value.trim() ? assetPayload() : {assets: []};
    var index = payload.assets.findIndex(function (asset) { return asset.asset_id === row.asset_id; });
    if (index >= 0) payload.assets[index] = Object.assign({}, payload.assets[index], row); else payload.assets.push(row);
    if (payload.assets.length > 500) throw new Error("每次最多编辑 500 条资产，请分批保存。");
    $("asset-json").value = JSON.stringify(payload, null, 2);
    assetImpactRequestVersions.declared += 1;
    $("asset-entry-message").textContent = "已" + (index >= 0 ? "更新" : "加入") + "编辑清单，尚未保存。请预览后点击保存清单。";
    clear($("asset-impact")); add($("asset-impact"), "p", "hint", "编辑清单已变化，请重新预览。");
  } catch (error) { showError(error); }
});

loadOverviewRisks();
