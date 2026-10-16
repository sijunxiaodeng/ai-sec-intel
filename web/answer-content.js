/* Deliberately small text-only formatter. Model/source HTML is never parsed. */
function renderAnswerContent(parent, value, citations) {
  var body = document.createElement("div"); body.className = "answer-body"; parent.appendChild(body);
  var lines = String(value == null ? "" : value).replace(/\r\n?/g, "\n").split("\n"), i = 0;
  function node(target, tag, text) { var el = document.createElement(tag); if (text != null) el.textContent = text; target.appendChild(el); return el; }
  function inline(target, text) {
    String(text).split(/(`[^`\n]+`|\*\*[^*\n]+\*\*|\[[^\]\n]+\])/g).forEach(function (part) {
      if (!part) return;
      if (part[0] === "`" && part[part.length - 1] === "`") node(target, "code", part.slice(1, -1));
      else if (part.slice(0, 2) === "**" && part.slice(-2) === "**") node(target, "strong", part.slice(2, -2));
      else if (citations && Object.prototype.hasOwnProperty.call(citations, part.slice(1, -1)) && part[0] === "[") {
        var link = node(target, "a", part); link.className = "citation-link";
        link.href = "#" + citations[part.slice(1, -1)]; link.setAttribute("aria-label", "定位证据 " + part);
      } else target.appendChild(document.createTextNode(part));
    });
  }
  function cells(line) { return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map(function (cell) { return cell.trim(); }); }
  function tableAt(index) { return index + 1 < lines.length && lines[index].includes("|") && cells(lines[index + 1]).every(function (cell) { return /^:?-{3,}:?$/.test(cell); }); }
  function special(index) { return /^\s*(```|#{1,4}\s|[-*+]\s|\d+[.)]\s)/.test(lines[index]) || tableAt(index); }
  while (i < lines.length) {
    var line = lines[i];
    if (!line.trim()) { i++; continue; }
    if (/^\s*```/.test(line)) {
      var code = []; i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) code.push(lines[i++]);
      if (i < lines.length) i++;
      node(node(body, "pre"), "code", code.join("\n")); continue;
    }
    if (tableAt(i)) {
      var wrap = node(body, "div"); wrap.className = "answer-table-wrap";
      var table = node(wrap, "table"); table.className = "answer-table";
      var head = node(node(table, "thead"), "tr");
      cells(lines[i]).forEach(function (cell) { var th = node(head, "th"); th.scope = "col"; inline(th, cell); }); i += 2;
      var tbody = node(table, "tbody");
      while (i < lines.length && lines[i].trim() && lines[i].includes("|")) {
        var tr = node(tbody, "tr"); cells(lines[i++]).forEach(function (cell) { inline(node(tr, "td"), cell); });
      }
      continue;
    }
    if (/^\s*#{1,4}\s/.test(line)) { inline(node(body, "h4"), line.replace(/^\s*#{1,4}\s+/, "")); i++; continue; }
    var ordered = /^\s*\d+[.)]\s/.test(line), unordered = /^\s*[-*+]\s/.test(line);
    if (ordered || unordered) {
      var list = node(body, ordered ? "ol" : "ul"), pattern = ordered ? /^\s*\d+[.)]\s+/ : /^\s*[-*+]\s+/;
      while (i < lines.length && pattern.test(lines[i])) inline(node(list, "li"), lines[i++].replace(pattern, ""));
      continue;
    }
    var paragraph = [line]; i++;
    while (i < lines.length && lines[i].trim() && !special(i)) paragraph.push(lines[i++]);
    inline(node(body, "p"), paragraph.join("\n"));
  }
  return body;
}
