"use strict";
// Extensions tab: turn third-party extensions on or off and review the issues
// they report. Issues arrive live over the event stream.

const extState = { exts: [], issues: new Map(), filter: "" };
const SEV_RANK = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

function issueVisible(is) {
  if (!extState.filter) return true;
  return (is.severity + " " + is.name + " " + is.ext + " " + (is.url || "") + " " + (is.detail || "")).toLowerCase().includes(extState.filter);
}
function issueRow(is) {
  return h("tr", {},
    h("td", { class: "num" }, is.id),
    h("td", {}, h("span", { class: "sev sev-" + is.severity }, is.severity)),
    h("td", { title: is.name }, is.name),
    h("td", { class: "dim" }, is.ext),
    h("td", { title: is.url || "" }, is.url || ""),
    h("td", { class: "num" }, is.flow ? "#" + is.flow : ""),
    h("td", { class: "dim" }, fmtTime(is.time)));
}
const issueTable = new SortTable($("xTable"), {
  key: "id", dir: "desc", render: issueRow, filter: issueVisible,
  values: { sev: (is) => SEV_RANK[is.severity] ?? 0, time: (is) => new Date(is.time).getTime(), flow: (is) => is.flow || 0 },
  onSelect: (is) => showIssue(is),
});

function updateExtCounts() {
  const n = extState.issues.size;
  $("xIssueCount").textContent = n || "";
  $("extCount").textContent = n || "";
  const shown = issueTable.visibleCount();
  $("xCount").textContent = n ? (shown === n ? fmtNum(n) + " issues" : `${fmtNum(shown)} of ${fmtNum(n)} shown`) : "";
  $("xEmpty").hidden = n > 0;
}

function showIssue(is) {
  const d = $("xDetail");
  d.textContent = "";
  const actions = [];
  if (is.flow) {
    actions.push(h("button", { class: "btn", onclick: () => openIssueFlow(is.flow) }, "View request #" + is.flow));
    actions.push(h("button", { class: "btn", onclick: () => issueToRepeater(is.flow) }, "Send to Repeater"));
    actions.push(h("button", { class: "btn", onclick: () => issueToPoc(is) }, "⊕ Add to PoC"));
  }
  d.append(
    h("div", { class: "x-detail-head" },
      h("span", { class: "sev sev-" + is.severity }, is.severity),
      h("b", {}, is.name),
      h("span", { class: "muted" }, " · " + is.ext),
      h("span", { class: "spacer" }),
      ...actions),
    is.url ? h("div", { class: "x-detail-url" }, is.url) : null,
    is.detail ? h("p", { class: "x-detail-body" }, is.detail) : null,
    is.evidence ? h("pre", { class: "x-ev" }, is.evidence) : null);
}

function openIssueFlow(id) {
  showTab("proxy", "p-history");
  if (app.flows.get(id)) histTable.select(id);
  else toast("Request #" + id + " is no longer in history.");
}
async function issueToRepeater(id) {
  try { const d = await loadFlow(id); sendToRepeater(targetURL(d), bytesToText(b64ToBytes(d.request))); }
  catch (err) { toast(err.message, true); }
}
async function issueToPoc(is) {
  try {
    const d = await loadFlow(is.flow);
    if (!poc.title) { poc.title = is.name; poc.severity = is.severity; pocSave(); }
    addToPoc(d);
  } catch (err) { toast(err.message, true); }
}

function addIssue(is) {
  extState.issues.set(is.id, is);
  issueTable.add(is);
  updateExtCounts();
  flash("extensions");
}

function renderExtList() {
  const list = $("xList");
  list.textContent = "";
  if (!extState.exts.length) {
    list.append(h("p", { class: "muted" }, "No extensions found. Drop one into the extensions folder and Rescan."));
    return;
  }
  for (const e of extState.exts) {
    const toggle = h("input", { type: "checkbox", onchange: (ev) => toggleExt(e.name, ev.target.checked) });
    toggle.checked = e.enabled;
    const dot = e.running ? "run" : (e.enabled ? "err" : "off");
    const dotText = e.running ? "running" : (e.enabled ? "stopped" : "disabled");
    list.append(h("div", { class: "x-ext" + (e.enabled ? " on" : "") },
      h("label", { class: "check x-ext-toggle", title: e.enabled ? "Disable" : "Enable" }, toggle),
      h("div", { class: "x-ext-main" },
        h("div", { class: "x-ext-top" },
          h("b", {}, e.name),
          e.version ? h("span", { class: "muted small" }, " v" + e.version) : null,
          e.author ? h("span", { class: "muted small" }, " · " + e.author) : null,
          h("span", { class: "x-dot " + dot, title: dotText })),
        e.description ? h("div", { class: "x-ext-desc" }, e.description) : null,
        h("div", { class: "muted small x-ext-meta" }, "events: " + (e.events || []).join(", ") + "  ·  " + (e.command || "")),
        e.error ? h("div", { class: "x-ext-err" }, e.error) : null),
      h("button", { class: "btn", onclick: () => showExtLogs(e.name) }, "Logs (" + e.logs + ")")));
  }
}

async function toggleExt(name, on) {
  try { setExts(await api("PUT", "/api/ext/" + encodeURIComponent(name), { enabled: on })); }
  catch (err) { toast(err.message, true); loadExtData(); }
}
async function reloadExts() {
  try { setExts(await api("POST", "/api/ext/reload")); toast("Rescanned the extensions folder."); }
  catch (err) { toast(err.message, true); }
}
async function showExtLogs(name) {
  try {
    const r = await getJSON("/api/ext/" + encodeURIComponent(name) + "/logs");
    $("xLogTitle").textContent = "Logs · " + name;
    $("xLogBody").textContent = (r.logs || []).join("\n") || "(no output yet)";
    $("xLogDialog").showModal();
  } catch (err) { toast(err.message, true); }
}

function setExts(list) {
  extState.exts = Array.isArray(list) ? list : [];
  renderExtList();
}

async function loadExtData() {
  try {
    const [exts, issues] = await Promise.all([getJSON("/api/ext"), getJSON("/api/ext/issues")]);
    setExts(exts);
    extState.issues.clear();
    issueTable.clear();
    for (const is of issues || []) { extState.issues.set(is.id, is); issueTable.add(is); }
    updateExtCounts();
  } catch (err) { toast("Could not load extensions: " + err.message, true); }
}

// ── wiring ──
on("issue", addIssue);
on("ext", setExts);
$("xFilter").addEventListener("input", (e) => { extState.filter = e.target.value.trim().toLowerCase(); issueTable.refilter(); updateExtCounts(); });
$("xClear").addEventListener("click", async () => {
  try { await api("DELETE", "/api/ext/issues"); extState.issues.clear(); issueTable.clear(); $("xDetail").textContent = ""; updateExtCounts(); }
  catch (err) { toast(err.message, true); }
});
$("xReload").addEventListener("click", reloadExts);
$("xLogClose").addEventListener("click", () => $("xLogDialog").close());
