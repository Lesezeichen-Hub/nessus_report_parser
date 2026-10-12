const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
const SEVERITY_BY_COLOR = new Map([
  ["#91243e", "Critical"],
  ["#dd4b50", "High"],
  ["#f18c43", "Medium"],
  ["#f8c851", "Low"],
  ["#67ace1", "Info"],
]);
const RISK_FACTOR = new Map(SEVERITIES.map(value => [value.toLowerCase(), value]));
const MAX_FILE_SIZE = 50 * 1024 * 1024;

const ui = {
  dropZone: document.getElementById("drop-zone"),
  fileInput: document.getElementById("file-input"),
  browseButton: document.getElementById("browse-button"),
  appMessage: document.getElementById("app-message"),
  dashboard: document.getElementById("dashboard"),
  fileName: document.getElementById("file-name"),
  reportMeta: document.getElementById("report-meta"),
  clearReport: document.getElementById("clear-report"),
  searchInput: document.getElementById("search-input"),
  issuesOnly: document.getElementById("issues-only"),
  resultsBody: document.getElementById("results-body"),
  resultCount: document.getElementById("result-count"),
  emptyResults: document.getElementById("empty-results"),
};

let hosts = [];
let expandedHosts = new Set();

function normalizeText(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function directText(element) {
  return [...element.childNodes]
    .filter(node => node.nodeType === Node.TEXT_NODE)
    .map(node => node.nodeValue)
    .join(" ");
}

function isHostHeading(element) {
  if (element.tagName !== "DIV") return false;
  const style = element.getAttribute("style") || "";
  return /font-size\s*:\s*22px/i.test(style) && /font-weight\s*:\s*700/i.test(style) && normalizeText(directText(element)) !== "";
}

function parseHostBlocks(sectionHeading) {
  const result = [];
  let current = null;

  for (let node = sectionHeading.nextElementSibling; node; node = node.nextElementSibling) {
    if (node.tagName === "H6") break;
    if (isHostHeading(node)) {
      if (current) result.push(current);
      current = { name: normalizeText(directText(node)), nodes: [node] };
    } else if (current) {
      current.nodes.push(node);
    }
  }
  if (current) result.push(current);
  return result;
}

function getSummaryCounts(block) {
  for (const node of block.nodes) {
    if (!node.matches(".table-wrapper")) continue;
    const table = node.querySelector("table");
    if (!table) continue;
    const rows = [...table.querySelectorAll("tr")];
    for (let index = 1; index < rows.length; index++) {
      const labels = [...rows[index].querySelectorAll("td")].map(cell => normalizeText(cell.textContent));
      if (!SEVERITIES.every(label => labels.some(value => value.toLowerCase() === label.toLowerCase()))) continue;

      const labelIndexes = SEVERITIES.map(label => labels.findIndex(value => value.toLowerCase() === label.toLowerCase()));
      const valueRow = rows[index - 1];
      const values = [...valueRow.querySelectorAll("td")].map(cell => normalizeText(cell.textContent));
      return Object.fromEntries(SEVERITIES.map((label, severityIndex) => {
        const raw = values[labelIndexes[severityIndex]] || "0";
        const count = Number.parseInt(raw.replace(/[^\d-]/g, ""), 10);
        return [label, Number.isFinite(count) ? count : 0];
      }));
    }
  }
  return null;
}

function readDetailValue(block, label) {
  for (const node of block.nodes) {
    if (!node.matches(".details-header") || normalizeText(node.textContent).toLowerCase() !== "host information") continue;
    let valueNode = node.nextElementSibling;
    while (valueNode && !valueNode.matches(".table-wrapper.details")) valueNode = valueNode.nextElementSibling;
    if (!valueNode) continue;
    for (const row of valueNode.querySelectorAll("tr")) {
      const cells = [...row.querySelectorAll("td")];
      if (cells.length < 2) continue;
      if (normalizeText(cells[0].textContent).replace(/:$/, "").toLowerCase() === label.toLowerCase()) {
        return normalizeText(cells[1].textContent);
      }
    }
  }
  return "";
}

function getRiskFactor(wrapper) {
  if (!wrapper) return "";
  const headers = [...wrapper.querySelectorAll(".details-header")];
  const header = headers.find(element => normalizeText(element.textContent).toLowerCase() === "risk factor");
  return header?.nextElementSibling ? normalizeText(header.nextElementSibling.textContent) : "";
}

function severityFromElement(element, wrapper) {
  const style = element.getAttribute("style") || "";
  const color = style.match(/background(?:-color)?\s*:\s*(#[\da-f]{3,8}|rgba?\([^)]*\))/i)?.[1]?.toLowerCase();
  const fromColor = color ? SEVERITY_BY_COLOR.get(color) : null;
  if (fromColor) return fromColor;
  return RISK_FACTOR.get(getRiskFactor(wrapper).toLowerCase()) || "";
}

function getFindings(block) {
  const findings = [];
  const seen = new Set();
  for (const node of block.nodes) {
    if (!node.matches('div[onclick*="toggleSection("]')) continue;
    const title = normalizeText(directText(node));
    const match = title.match(/^(\d+)\s*[-–:]\s*(.+)$/);
    const wrapper = node.nextElementSibling?.classList.contains("section-wrapper") ? node.nextElementSibling : null;
    const severity = severityFromElement(node, wrapper);
    if (!severity || !["Critical", "High", "Medium"].includes(severity)) continue;
    const key = `${match?.[1] || ""}:${title}:${severity}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({ pluginId: match?.[1] || "", title: match?.[2] || title || "Nessus-Plugin", severity });
  }
  return findings;
}

function parseReport(html) {
  const report = new DOMParser().parseFromString(html, "text/html");
  const section = [...report.querySelectorAll("h6")].find(heading =>
    normalizeText(directText(heading)).toLowerCase() === "vulnerabilities by host");
  if (!section) throw new Error("Der Abschnitt „Vulnerabilities by Host“ wurde nicht gefunden. Bitte einen Nessus-HTML-Export verwenden.");

  const blocks = parseHostBlocks(section);
  if (!blocks.length) throw new Error("Im Host-Abschnitt wurden keine Hosts erkannt. Das HTML-Format wird möglicherweise nicht unterstützt.");

  return blocks.map(block => {
    const counts = getSummaryCounts(block);
    const findings = getFindings(block);
    const critical = counts?.Critical ?? findings.filter(finding => finding.severity === "Critical").length;
    const high = counts?.High ?? findings.filter(finding => finding.severity === "High").length;
    const medium = counts?.Medium ?? findings.filter(finding => finding.severity === "Medium").length;
    return {
      name: block.name,
      dns: readDetailValue(block, "DNS Name"),
      ip: readDetailValue(block, "IP"),
      critical,
      high,
      medium,
      findings,
    };
  });
}

function setMessage(message, isSuccess = false) {
  ui.appMessage.textContent = message;
  ui.appMessage.classList.toggle("success", isSuccess);
  ui.appMessage.hidden = !message;
}

function formatNumber(value) {
  return new Intl.NumberFormat("de-DE").format(value);
}

function formatFileSize(bytes) {
  if (bytes < 1024 * 1024) return `${formatNumber(Math.round(bytes / 1024))} KB`;
  return `${(bytes / (1024 * 1024)).toLocaleString("de-DE", { maximumFractionDigits: 1 })} MB`;
}

function addCell(row, content, className = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  if (content instanceof Node) cell.append(content);
  else cell.textContent = content;
  row.append(cell);
  return cell;
}

function createFindingList(host) {
  const list = document.createElement("div");
  list.className = "finding-list";
  const findings = host.findings.filter(finding => ["Critical", "High", "Medium"].includes(finding.severity));
  if (!findings.length) {
    const note = document.createElement("p");
    note.className = "finding-note";
    note.textContent = "Der Host-Zähler meldet Findings, aber die Plugin-Details konnten in diesem Export nicht ausgelesen werden.";
    list.append(note);
    return list;
  }
  for (const finding of findings) {
    const item = document.createElement("div");
    item.className = "finding-item";
    const badge = document.createElement("span");
    badge.className = `finding-severity ${finding.severity.toLowerCase()}`;
    badge.textContent = finding.severity;
    const title = document.createElement("span");
    title.className = "finding-title";
    if (finding.pluginId) {
      const id = document.createElement("span");
      id.className = "plugin-id";
      id.textContent = `#${finding.pluginId}`;
      title.append(id);
    }
    title.append(document.createTextNode(finding.title));
    item.append(badge, title);
    list.append(item);
  }
  return list;
}

function renderResults() {
  const query = ui.searchInput.value.trim().toLocaleLowerCase("de-DE");
  const issuesOnly = ui.issuesOnly.checked;
  const sorted = [...hosts].sort((a, b) => (b.critical - a.critical) || (b.high - a.high) || (b.medium - a.medium) || a.name.localeCompare(b.name, "de"));
  const visibleHosts = sorted.filter(host => {
    const matchesQuery = !query || [host.name, host.dns, host.ip].some(value => value.toLocaleLowerCase("de-DE").includes(query));
    return matchesQuery && (!issuesOnly || host.critical > 0 || host.high > 0);
  });

  ui.resultsBody.replaceChildren();
  for (const host of visibleHosts) {
    const row = document.createElement("tr");
    row.className = "data-row";
    const domain = document.createElement("div");
    domain.className = "host-cell";
    const name = document.createElement("span");
    name.className = "host-name";
    name.textContent = host.name;
    domain.append(name);
    if (host.dns && host.dns.toLowerCase() !== host.name.toLowerCase()) {
      const dns = document.createElement("span");
      dns.className = "dns-name";
      dns.title = host.dns;
      dns.textContent = host.dns;
      domain.append(dns);
    }
    addCell(row, domain);
    addCell(row, host.ip || "–", "ip-cell");

    const criticalCell = addCell(row, "", "severity-column");
    const critical = document.createElement("span");
    critical.className = `severity-count${host.critical ? " critical" : ""}`;
    critical.textContent = formatNumber(host.critical);
    criticalCell.append(critical);

    const highCell = addCell(row, "", "severity-column");
    const high = document.createElement("span");
    high.className = `severity-count${host.high ? " high" : ""}`;
    high.textContent = formatNumber(host.high);
    highCell.append(high);

    const mediumCell = addCell(row, "", "severity-column");
    const medium = document.createElement("span");
    medium.className = `severity-count${host.medium ? " medium" : ""}`;
    medium.textContent = formatNumber(host.medium);
    mediumCell.append(medium);

    const hasIssues = host.critical > 0 || host.high > 0;
    const hasMedium = host.medium > 0;
    const status = document.createElement("span");
    status.className = `status-badge${hasIssues ? " attention" : hasMedium ? " medium-only" : ""}`;
    status.textContent = hasIssues ? "Priorität: Critical / High" : hasMedium ? "Medium-Findings" : "Keine Critical / High / Medium";
    addCell(row, status);

    const detailCell = document.createElement("td");
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "detail-button";
    toggle.textContent = expandedHosts.has(host.name) ? "Schließen" : "Details";
    toggle.setAttribute("aria-expanded", String(expandedHosts.has(host.name)));
    toggle.addEventListener("click", () => {
      if (expandedHosts.has(host.name)) expandedHosts.delete(host.name);
      else expandedHosts.add(host.name);
      renderResults();
    });
    detailCell.append(toggle);
    row.append(detailCell);
    ui.resultsBody.append(row);

    if (expandedHosts.has(host.name)) {
      const detailRow = document.createElement("tr");
      detailRow.className = "detail-row";
      const detail = document.createElement("td");
      detail.colSpan = 7;
      detail.append(createFindingList(host));
      detailRow.append(detail);
      ui.resultsBody.append(detailRow);
    }
  }

  ui.resultCount.textContent = `${formatNumber(visibleHosts.length)} ${visibleHosts.length === 1 ? "Domain" : "Domains"}`;
  ui.emptyResults.hidden = visibleHosts.length > 0;
}

function updateDashboard(file) {
  const criticalHosts = hosts.filter(host => host.critical > 0).length;
  const highHosts = hosts.filter(host => host.high > 0).length;
  const mediumHosts = hosts.filter(host => host.medium > 0).length;
  const affectedHosts = hosts.filter(host => host.critical > 0 || host.high > 0).length;
  const criticalFindings = hosts.reduce((total, host) => total + host.critical, 0);
  const highFindings = hosts.reduce((total, host) => total + host.high, 0);
  const mediumFindings = hosts.reduce((total, host) => total + host.medium, 0);

  ui.fileName.textContent = file.name;
  ui.reportMeta.textContent = `${formatNumber(hosts.length)} Hosts erkannt · ${formatFileSize(file.size)} · lokal analysiert`;
  document.getElementById("stat-hosts").textContent = formatNumber(hosts.length);
  document.getElementById("stat-critical").textContent = formatNumber(criticalFindings);
  document.getElementById("stat-high").textContent = formatNumber(highFindings);
  document.getElementById("stat-medium").textContent = formatNumber(mediumFindings);
  document.getElementById("stat-affected").textContent = formatNumber(affectedHosts);
  document.getElementById("stat-critical-hosts").textContent = `${formatNumber(criticalHosts)} betroffene ${criticalHosts === 1 ? "Domain" : "Domains"}`;
  document.getElementById("stat-high-hosts").textContent = `${formatNumber(highHosts)} betroffene ${highHosts === 1 ? "Domain" : "Domains"}`;
  document.getElementById("stat-medium-hosts").textContent = `${formatNumber(mediumHosts)} betroffene ${mediumHosts === 1 ? "Domain" : "Domains"}`;
  ui.dashboard.hidden = false;
  ui.searchInput.value = "";
  ui.issuesOnly.checked = false;
  renderResults();
}

async function loadReport(file) {
  if (!file) return;
  if (!/\.html?$/i.test(file.name) && file.type !== "text/html") {
    setMessage("Bitte eine Nessus-HTML-Datei (.html oder .htm) auswählen.");
    return;
  }
  if (file.size > MAX_FILE_SIZE) {
    setMessage("Die Datei ist größer als 50 MB. Bitte einen kleineren HTML-Export auswählen.");
    return;
  }
  ui.dashboard.hidden = true;
  hosts = [];
  expandedHosts.clear();
  setMessage("Bericht wird lokal analysiert …", true);
  ui.dropZone.classList.add("loading");
  try {
    const report = parseReport(await file.text());
    hosts = report;
    expandedHosts = new Set();
    updateDashboard(file);
    setMessage(`Bericht erfolgreich analysiert: ${formatNumber(hosts.length)} Hosts gefunden.`, true);
  } catch (error) {
    setMessage(error.message || "Der Nessus-Bericht konnte nicht gelesen werden.");
  } finally {
    ui.dropZone.classList.remove("loading");
    ui.fileInput.value = "";
  }
}

function clearReport() {
  hosts = [];
  expandedHosts.clear();
  ui.dashboard.hidden = true;
  ui.searchInput.value = "";
  ui.dropZone.classList.remove("loading");
  setMessage("");
  ui.fileInput.value = "";
}

ui.dropZone.addEventListener("click", event => {
  if (event.target.closest("button")) return;
  ui.fileInput.click();
});
ui.dropZone.addEventListener("keydown", event => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    ui.fileInput.click();
  }
});
ui.browseButton.addEventListener("click", () => ui.fileInput.click());
ui.fileInput.addEventListener("change", event => loadReport(event.target.files?.[0]));
ui.clearReport.addEventListener("click", clearReport);
ui.searchInput.addEventListener("input", renderResults);
ui.issuesOnly.addEventListener("change", renderResults);

for (const eventName of ["dragenter", "dragover"]) {
  ui.dropZone.addEventListener(eventName, event => {
    event.preventDefault();
    ui.dropZone.classList.add("dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  ui.dropZone.addEventListener(eventName, event => {
    event.preventDefault();
    if (eventName === "drop") loadReport(event.dataTransfer?.files?.[0]);
    ui.dropZone.classList.remove("dragging");
  });
}
// Ende der Drag-and-drop-Handler.
// Datei-Ende.

