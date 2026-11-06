"use strict";
// Intruder: attack configurations in numbered tabs, and an attack results window.

const M = "§";
const int = {
  tabs: store.get("int.tabs", []),
  active: store.get("int.active", null),
  set: 0,                 // payload set shown in the editor
  attacks: new Map(),     // attack id -> {status, results: Map, count, positions, type}
  shown: null,            // attack id in the results window
};
int.next = int.tabs.reduce((m, t) => Math.max(m, t.id), 0) + 1;

const newSet = () => ({ type: "list", list: "", from: 1, to: 100, step: 1 });
function intSave() { store.set("int.tabs", int.tabs.map(({ attackId, ...t }) => t)); store.set("int.active", int.active); }
const intTab = () => int.tabs.find((t) => t.id === int.active);

function sendToIntruder(target, raw) {
  const t = { id: int.next++, type: "sniper", target, template: autoMark(raw.replace(/\r\n/g, "\n")), sets: [newSet()], encode: true, conc: 5, delay: 0 };
  int.tabs.push(t);
  int.active = t.id;
  intSave();
  flash("intruder");
  renderIntruder();
  toast("Sent to Intruder (tab " + t.id + "). Parameter values are marked; adjust the § positions as needed.");
}

const positionsOf = (tpl) => Math.floor((tpl.split(M).length - 1) / 2);
const setsNeeded = (t) => (t.type === "sniper" || t.type === "battering_ram" ? 1 : Math.max(positionsOf(t.template), 1));
function payloadValues(s) {
  if (s.type === "numbers") {
    const step = Number(s.step) || 1, from = Number(s.from), to = Number(s.to);
    if ((step > 0 && from > to) || (step < 0 && from < to)) return [];
    return { length: Math.floor((to - from) / step) + 1 };
  }
  return s.list.split(/\r?\n/).filter((l) => l !== "");
}
function requestCount(t) {
  const pos = positionsOf(t.template);
  const counts = t.sets.slice(0, setsNeeded(t)).map((s) => payloadValues(s).length);
  switch (t.type) {
    case "sniper": return pos * (counts[0] || 0);
    case "battering_ram": return pos ? counts[0] || 0 : 0;
    case "pitchfork": return pos ? Math.min(...counts) : 0;
    case "cluster_bomb": return pos ? counts.reduce((a, b) => a * b, 1) : 0;
  }
  return 0;
}

function renderIntruder() {
  if (!int.tabs.length) {
    int.tabs.push({ id: int.next++, type: "sniper", target: "https://example.com", sets: [newSet()], encode: true, conc: 5, delay: 0,
      template: "GET /?q=" + M + "test" + M + " HTTP/1.1\nHost: example.com\nUser-Agent: loupe\n\n" });
  }
  if (!intTab()) int.active = int.tabs[int.tabs.length - 1].id;
  const bar = $("intTabs");
  bar.textContent = "";
  for (const t of int.tabs) {
    bar.append(h("button", { class: t.id === int.active ? "active" : "", onclick: () => { int.active = t.id; int.set = 0; intSave(); renderIntruder(); } },
      String(t.id), h("span", { class: "x", title: "Close tab", onclick: (e) => {
        e.stopPropagation(); int.tabs = int.tabs.filter((o) => o.id !== t.id); intSave(); renderIntruder();
      } }, "×")));
  }
  bar.append(h("button", { title: "New tab", onclick: () => { const a = intTab(); sendToIntruder(a.target, a.template.split(M).join("")); } }, "+"));
  const t = intTab();
  $("intType").value = t.type;
  $("intTarget").value = t.target;
  $("intTemplate").value = t.template;
  $("intEncode").checked = t.encode;
  $("intConc").value = t.conc;
  $("intDelay").value = t.delay;
  $("intResults").hidden = !t.attackId;
  renderPayloads();
}

function renderPayloads() {
  const t = intTab();
  const need = setsNeeded(t);
  while (t.sets.length < need) t.sets.push(newSet());
  int.set = Math.min(int.set, need - 1);
  const sel = $("intSet");
  sel.textContent = "";
  for (let i = 0; i < need; i++) sel.append(h("option", { value: i }, String(i + 1)));
  sel.value = int.set;
  const s = t.sets[int.set];
  $("intPType").value = s.type;
  $("intListBox").hidden = s.type !== "list";
  $("intNumBox").hidden = s.type !== "numbers";
  $("intList").value = s.list;
  $("intFrom").value = s.from; $("intTo").value = s.to; $("intStep").value = s.step;
  updateCounts();
}
function updateCounts() {
  const t = intTab();
  const pos = positionsOf(t.template);
  $("intPosInfo").textContent = pos + " payload position" + (pos === 1 ? "" : "s") + (t.template.split(M).length % 2 === 0 ? " — unpaired § marker" : "");
  $("intCounts").textContent = "Payload count: " + fmtNum(payloadValues(t.sets[int.set]).length) + " · Request count: " + fmtNum(requestCount(t));
}

// autoMark puts § around query, form and JSON values and cookie values, like Burp's Auto §.
function autoMark(text) {
  text = text.split(M).join("");
  const [head, body] = splitMessage(text);
  const lines = head.split("\n");
  lines[0] = lines[0].replace(/([?&][^=&\s#]+=)([^&\s#]*)/g, (_, k, v) => k + M + v + M);
  for (let i = 1; i < lines.length; i++) {
    if (/^cookie:/i.test(lines[i])) lines[i] = lines[i].replace(/([:;]\s*[^=;\s]+=)([^;\r]*)/g, (_, k, v) => k + M + v + M);
  }
  let b = body;
  const t = b.trim();
  if (t.startsWith("{") || t.startsWith("[")) {
    b = b.replace(/("(?:[^"\\]|\\.)*"\s*:\s*)("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false)/g, (_, k, v) =>
      v.startsWith('"') ? k + '"' + M + v.slice(1, -1) + M + '"' : k + M + v + M);
  } else if (t && /^[^=&\s]+=/.test(t)) {
    b = b.replace(/(^|&)([^=&\s]+=)([^&\r\n]*)/g, (_, s, k, v) => s + k + M + v + M);
  }
  return lines.join("\n") + b;
}

function bindTab(id, key, parse = (v) => v) {
  $(id).addEventListener("input", (e) => { const t = intTab(); t[key] = parse(e.target.type === "checkbox" ? e.target.checked : e.target.value); intSave(); updateCounts(); });
}
bindTab("intTarget", "target", (v) => v.trim());
bindTab("intTemplate", "template");
bindTab("intConc", "conc", Number);
bindTab("intDelay", "delay", Number);
$("intEncode").addEventListener("change", (e) => { intTab().encode = e.target.checked; intSave(); });
$("intType").addEventListener("change", (e) => { intTab().type = e.target.value; intSave(); renderPayloads(); });
$("intSet").addEventListener("change", (e) => { int.set = Number(e.target.value); renderPayloads(); });
$("intPType").addEventListener("change", (e) => { intTab().sets[int.set].type = e.target.value; intSave(); renderPayloads(); });
$("intList").addEventListener("input", (e) => { intTab().sets[int.set].list = e.target.value; intSave(); updateCounts(); });
for (const [id, key] of [["intFrom", "from"], ["intTo", "to"], ["intStep", "step"]]) {
  $(id).addEventListener("input", (e) => { intTab().sets[int.set][key] = Number(e.target.value); intSave(); updateCounts(); });
}
function setList(v) { intTab().sets[int.set].list = v; $("intList").value = v; intSave(); updateCounts(); }
$("intPaste").addEventListener("click", async () => {
  try { const cur = $("intList").value; const add = await navigator.clipboard.readText(); setList(cur && !cur.endsWith("\n") ? cur + "\n" + add : cur + add); }
  catch { toast("Could not read the clipboard.", true); }
});
$("intLoad").addEventListener("click", () => $("intFile").click());
$("intFile").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (file) setList((await file.text()).replace(/\r\n/g, "\n"));
  e.target.value = "";
});
$("intDedupe").addEventListener("click", () => setList([...new Set($("intList").value.split("\n"))].join("\n")));
$("intClearList").addEventListener("click", () => setList(""));

function editTemplate(fn) {
  const ta = $("intTemplate");
  const [s, e] = [ta.selectionStart, ta.selectionEnd];
  ta.value = fn(ta.value, s, e);
  intTab().template = ta.value; intSave(); updateCounts(); ta.focus();
}
$("intAdd").addEventListener("click", () => editTemplate((v, s, e) => v.slice(0, s) + M + v.slice(s, e) + M + v.slice(e)));
$("intClear").addEventListener("click", () => editTemplate((v) => v.split(M).join("")));
$("intAuto").addEventListener("click", () => editTemplate((v) => autoMark(v)));

$("intStart").addEventListener("click", async () => {
  const t = intTab();
  t.template = $("intTemplate").value;
  const need = setsNeeded(t);
  const sets = t.sets.slice(0, need).map((s) => s.type === "numbers"
    ? { type: "numbers", from: Number(s.from), to: Number(s.to), step: Number(s.step) || 1 }
    : { type: "list", list: payloadValues(s) });
  try {
    const st = await api("POST", "/api/intruder", {
      targetUrl: t.target, template: t.template, type: t.type, sets, urlEncode: t.encode, concurrency: t.conc, delayMs: t.delay,
    });
    t.attackId = st.id;
    int.attacks.set(st.id, { status: st, results: new Map(), count: payloadValues(t.sets[0]).length, positions: positionsOf(t.template), type: t.type });
    $("intResults").hidden = false;
    openAttack(st.id);
  } catch (err) { toast(err.message, true); }
});
$("intResults").addEventListener("click", () => { const t = intTab(); if (t.attackId) openAttack(t.attackId); });

// ── Attack results window ──
const TYPE_NAMES = { sniper: "Sniper", battering_ram: "Battering ram", pitchfork: "Pitchfork", cluster_bomb: "Cluster bomb" };
let awTable = null, awFilter = "";
const awPair = makePair($("awPair"));
hsplit($("attackWin").querySelector(".hsplit"), $("attackWin").querySelector(".win"));

function openAttack(id) {
  const a = int.attacks.get(id);
  if (!a) return;
  int.shown = id;
  $("attackWin").hidden = false;
  const table = $("awTable");
  const cols = [["n", "Request", 80]];
  if (a.type === "sniper") cols.push(["pos", "Position", 80], ["p0", "Payload", 0]);
  else if (a.type === "battering_ram") cols.push(["p0", "Payload", 0]);
  else for (let i = 0; i < a.positions; i++) cols.push(["p" + i, "Payload " + (i + 1), 0]);
  cols.push(["status", "Status code", 95], ["error", "Error", 150], ["length", "Length", 90], ["ms", "Time (ms)", 90]);
  const tbody = h("tbody");
  table.replaceChildren(
    h("colgroup", {}, cols.map(([, , w]) => h("col", { style: w ? `width:${w}px` : "" }))),
    h("thead", {}, h("tr", {}, cols.map(([k, label]) => h("th", { class: "sort" + (["length", "ms", "n", "status"].includes(k) ? " r" : ""), "data-key": k }, label)))),
    tbody);
  const values = { pos: (r) => sniperPos(a, r) };
  for (let i = 0; i < Math.max(a.positions, 1); i++) values["p" + i] = (r) => (a.type === "sniper" ? r.payloads[sniperPos(a, r) - 1] : r.payloads[i]);
  awTable = new SortTable(table, {
    key: "n", values,
    render: (r) => h("tr", {}, cols.map(([k]) => {
      const v = values[k] ? values[k](r) : r[k];
      return h("td", { class: k === "error" && v ? "err" : ["length", "ms", "n", "status"].includes(k) ? "r" : "", title: typeof v === "string" ? v : null },
        k === "length" ? fmtNum(v || 0) : v === 0 && k === "status" ? "" : v ?? "");
    })),
    filter: (r) => !awFilter || (r.payloads.join(" ") + " " + r.status + " " + (r.error || "")).toLowerCase().includes(awFilter),
    onSelect: async (r) => {
      const d = await getJSON(`/api/intruder/${id}/results/${r.n}`).catch((err) => { toast(err.message, true); return null; });
      if (!d || awTable.selected !== r.n) return;
      awPair.req.set(b64ToBytes(d.request));
      awPair.resp.set(b64ToBytes(d.response), d.responseDecoded ? b64ToBytes(d.responseDecoded) : null, d.error || "No response.");
    },
    onMenu: (e, r) => showMenu(e, [
      { label: "Send to Repeater", action: async () => { const d = await getJSON(`/api/intruder/${id}/results/${r.n}`); sendToRepeater(a.status.target, bytesToText(b64ToBytes(d.request))); } },
      { label: "Copy payload", action: () => copyText(r.payloads.join(", "), "Payload") },
      { label: "✦ Ask " + aiName(), action: async () => {
        const d = await getJSON(`/api/intruder/${id}/results/${r.n}`);
        askClaude({ key: `int:${id}:${r.n}`, title: `Attack ${id} request ${r.n} · payload ${r.payloads.join(", ")}`, target: a.status.target,
          note: `Intruder attack ${id}, request ${r.n}, payload(s): ${r.payloads.join(", ")}`,
          request: messageText(d.request), response: messageText(d.response, d.responseDecoded) });
      } },
    ]),
  });
  awPair.req.set(null); awPair.resp.set(null);
  for (const r of a.results.values()) awTable.add(r);
  renderAttackStatus();
  if (!a.loaded) {
    a.loaded = true;
    getJSON("/api/intruder/" + id).then((st) => {
      a.status = st;
      for (const r of st.results || []) { a.results.set(r.n, r); if (int.shown === id) awTable.add(r); }
      renderAttackStatus();
    }).catch(() => {});
  }
}
function sniperPos(a, r) { return a.count ? Math.floor((r.n - 1) / a.count) + 1 : 1; }
function renderAttackStatus() {
  const a = int.attacks.get(int.shown);
  if (!a) return;
  const s = a.status;
  $("awTitle").textContent = `Attack ${s.id} · ${TYPE_NAMES[s.type] || s.type} · ${s.target}`;
  $("awBar").max = Math.max(s.total, 1); $("awBar").value = a.results.size;
  $("awProg").textContent = (s.done ? (s.stopped ? "Stopped" : "Finished") : "Running") + ` · ${fmtNum(a.results.size)} of ${fmtNum(s.total)} requests`;
  $("awStop").disabled = s.done;
}
on("intruder", ({ status, result }) => {
  const a = int.attacks.get(status.id);
  if (!a) return;
  a.status = status;
  if (result) { a.results.set(result.n, result); if (int.shown === status.id && awTable) awTable.add(result); }
  else if (int.shown === status.id) {
    // Events can be dropped under load; reconcile with the full list at the end.
    getJSON("/api/intruder/" + status.id).then((st) => {
      for (const r of st.results || []) if (!a.results.has(r.n)) { a.results.set(r.n, r); awTable.add(r); }
      a.status = st; renderAttackStatus();
    });
  }
  if (int.shown === status.id) renderAttackStatus();
});
$("awStop").addEventListener("click", () => api("POST", `/api/intruder/${int.shown}/stop`).catch((err) => toast(err.message, true)));
$("awClose").addEventListener("click", () => { $("attackWin").hidden = true; });
$("awFilter").addEventListener("input", (e) => { awFilter = e.target.value.trim().toLowerCase(); awTable?.refilter(); });
addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("attackWin").hidden && !document.querySelector("dialog[open]")) $("attackWin").hidden = true; });
