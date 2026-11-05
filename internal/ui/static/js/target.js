"use strict";
// Target tab: site map built from the history, and the scope.

const sm = { sel: null, expanded: new Set(store.get("sm.expanded", [])), scopeOnly: store.get("sm.scopeOnly", false), hideNoise: store.get("sm.hideNoise", true), dirty: true };

function smOrigin(f) { return (f.tls ? "https://" : "http://") + f.host; }
function smPath(f) { return (f.path || "/").split("?")[0]; }
function smIncluded(f) {
  if (f.method === "CONNECT") return false;
  if (sm.scopeOnly && !f.inScope) return false;
  if (sm.hideNoise && f.noise) return false;
  return true;
}

function renderSiteMap() {
  sm.dirty = false;
  const tree = $("smTree");
  const hosts = new Map(); // origin -> {inScope, paths:Set}
  for (const f of app.flows.values()) {
    if (!smIncluded(f)) continue;
    const o = smOrigin(f);
    if (!hosts.has(o)) hosts.set(o, { inScope: f.inScope, paths: new Set() });
    hosts.get(o).paths.add(smPath(f));
  }
  tree.textContent = "";
  if (!hosts.size) { tree.append(h("div", { class: "empty" }, "Browse through the proxy to build the site map.")); return; }
  for (const o of [...hosts.keys()].sort()) {
    const info = hosts.get(o), open = sm.expanded.has(o);
    const node = h("div", { class: "node" + (sm.sel === o ? " sel" : "") + (app.scope.length && !info.inScope ? " out" : ""), title: o },
      h("span", { class: "twisty", onclick: (e) => { e.stopPropagation(); open ? sm.expanded.delete(o) : sm.expanded.add(o); store.set("sm.expanded", [...sm.expanded]); renderSiteMap(); } }, open ? "▾" : "▸"),
      o);
    node.addEventListener("click", () => selectNode(o));
    node.addEventListener("contextmenu", (e) => hostMenu(e, o));
    tree.append(node);
    if (!open) continue;
    for (const p of [...info.paths].sort()) {
      const key = o + p;
      const child = h("div", { class: "node child" + (sm.sel === key ? " sel" : ""), title: key }, p);
      child.addEventListener("click", () => selectNode(key));
      tree.append(child);
    }
  }
}
function hostMenu(e, origin) {
  const host = hostOnly(new URL(origin).host);
  const inScope = app.scope.includes(host);
  showMenu(e, [
    inScope ? { label: "Remove from scope", action: () => setScope(app.scope.filter((p) => p !== host)) }
      : { label: "Add to scope", action: () => setScope([...app.scope, host]).then(() => toast(host + " added to scope.")) },
    { label: "Add *." + host.replace(/^www\./, "") + " to scope", action: () => setScope([...app.scope, "*." + host.replace(/^www\./, "")]) },
    "-",
    { label: "Copy URL", action: () => copyText(origin, "URL") },
  ]);
}

const smTable = new SortTable($("smTable"), {
  render: (f) => h("tr", {}, h("td", { class: "num" }, f.id), h("td", {}, f.method), h("td", { title: f.url }, f.path),
    h("td", { class: f.error ? "err" : "" }, f.error ? "Error" : f.status || ""), h("td", { class: "r" }, f.respSize ? fmtNum(f.respSize) : ""), h("td", {}, f.mime || "")),
  values: { url: (f) => f.path },
  onSelect: async (f) => {
    const d = await loadFlow(f.id).catch(() => null);
    if (!d || smTable.selected !== f.id) return;
    smPair.req.set(b64ToBytes(d.request));
    smPair.resp.set(b64ToBytes(d.response), d.responseDecoded ? b64ToBytes(d.responseDecoded) : null);
  },
  onMenu: (e, f) => flowMenu(e, f, () => loadFlow(f.id)),
});
const smPair = makePair($("smPair"));
vsplit($("t-sitemap").querySelector(".vsplit"), $("t-sitemap"));
hsplit($("t-sitemap").querySelector(".hsplit"), $("t-sitemap").querySelector(".sm-right"));

function selectNode(key) {
  sm.sel = key;
  renderSiteMap();
  smTable.clear();
  for (const f of app.flows.values()) {
    if (!smIncluded(f)) continue;
    const o = smOrigin(f);
    if (key === o || key === o + smPath(f)) smTable.add(f);
  }
  $("smCount").textContent = fmtNum(smTable.rows.size) + " items";
}

for (const [id, key] of [["smScopeOnly", "scopeOnly"], ["smHideNoise", "hideNoise"]]) {
  $(id).checked = sm[key];
  $(id).addEventListener("change", (e) => { sm[key] = e.target.checked; store.set("sm." + key, sm[key]); renderSiteMap(); if (sm.sel) selectNode(sm.sel); });
}
let smTimer = 0;
on("flowAdded", (f) => {
  sm.dirty = true;
  if (app.tab !== "target") return;
  clearTimeout(smTimer);
  smTimer = setTimeout(() => {
    renderSiteMap();
    if (sm.sel && (sm.sel === smOrigin(f) || sm.sel === smOrigin(f) + smPath(f)) && smIncluded(f)) smTable.add(f);
  }, 300);
});
on("tabShown", (tab) => { if (tab === "target" && sm.dirty) renderSiteMap(); });

// ── Scope ──
function renderScope() {
  const tbody = $("scopeRows");
  tbody.textContent = "";
  if (!app.scope.length) tbody.append(h("tr", {}, h("td", { colspan: 2, class: "dim" }, "Empty — every host is in scope.")));
  for (const p of app.scope) {
    tbody.append(h("tr", {}, h("td", {}, h("code", {}, p)),
      h("td", { class: "c" }, h("button", { class: "btn", onclick: () => setScope(app.scope.filter((x) => x !== p)).catch((err) => toast(err.message, true)) }, "Remove"))));
  }
}
async function addScope(lines) {
  try { await setScope([...app.scope, ...lines]); $("scopeNew").value = ""; }
  catch (err) { toast(err.message, true); }
}
$("scopeAdd").addEventListener("click", () => $("scopeNew").value.trim() && addScope([$("scopeNew").value]));
$("scopeNew").addEventListener("keydown", (e) => { if (e.key === "Enter") $("scopeAdd").click(); });
$("scopePaste").addEventListener("click", async () => {
  try { addScope((await navigator.clipboard.readText()).split(/\r?\n/)); } catch { toast("Could not read the clipboard.", true); }
});
$("scopeClear").addEventListener("click", () => setScope([]));
on("scopeChanged", () => {
  renderScope();
  $$("#mainTabs button")[0].title = app.scope.length ? app.scope.length + " host(s) in scope" : "";
  if (app.tab === "target") renderSiteMap(); else sm.dirty = true;
});
on("scope", (s) => { app.scope = s.patterns || []; emit("scopeChanged"); });
