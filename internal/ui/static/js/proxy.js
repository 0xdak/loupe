"use strict";
// Proxy tab: Intercept, HTTP history, WebSockets history, Match and replace, settings.

// ═════════════ HTTP history ═════════════
const STATIC_MIME = new Set(["CSS", "image", "font", "binary", "media"]);
const STATIC_EXT = new Set(["css", "png", "jpg", "jpeg", "gif", "webp", "avif", "ico", "svg", "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3"]);
const hist = {
  filter: "", scopeOnly: store.get("h.scopeOnly", false), hideNoise: store.get("h.hideNoise", true),
  hideStatic: store.get("h.hideStatic", true), follow: true, detail: null, showOriginal: false, lastId: 0,
};

function histVisible(f) {
  if (hist.scopeOnly && !f.inScope) return false;
  if (hist.hideNoise && f.noise) return false;
  if (hist.hideStatic && (STATIC_MIME.has(f.mime) || STATIC_EXT.has(f.ext))) return false;
  if (!hist.filter) return true;
  return (f.method + " " + f.url + " " + (f.error ? "error" : f.status) + " " + (f.mime || "") + " " + (f.note || "")).toLowerCase().includes(hist.filter);
}

function histRow(f) {
  const status = f.error ? h("td", { class: "err", title: f.error }, f.status || "Error") : h("td", {}, f.status || "");
  let path = f.method === "CONNECT" ? (f.error ? "(TLS rejected — the client does not trust the lightproxy CA)" : "(tunnel — not decrypted)") : f.path;
  return h("tr", {},
    h("td", { class: "num" }, f.id),
    h("td", { title: f.host }, (f.tls ? "https://" : "http://") + f.host),
    h("td", {}, f.method),
    h("td", { title: f.url }, path, f.source === "repeater" ? h("span", { class: "muted" }, "  [Repeater]") : null),
    h("td", { class: "c" }, f.params ? "✓" : ""),
    h("td", { class: "c" }, f.edited ? "✓" : ""),
    status,
    h("td", { class: "r" }, f.respSize ? fmtNum(f.respSize) : ""),
    h("td", {}, f.mime || ""),
    h("td", {}, f.ext || ""),
    h("td", { class: "c" }, f.tls ? "✓" : ""),
    h("td", { class: "dim" }, fmtTime(f.start)),
  );
}

const histTable = new SortTable($("hTable"), {
  render: histRow, filter: histVisible,
  values: { params: (f) => (f.params ? 1 : 0), edited: (f) => (f.edited ? 1 : 0), tls: (f) => (f.tls ? 1 : 0), start: (f) => f.start, status: (f) => (f.error ? 999 : f.status) },
  onSelect: (f) => showHistDetail(f.id),
  onMenu: (e, f) => flowMenu(e, f, () => loadFlow(f.id)),
});
const histPair = makePair($("hPair"));
hsplit($("p-history").querySelector(".hsplit"), $("p-history"));

function histCount() {
  const total = histTable.rows.size, shown = histTable.visibleCount();
  $("hCount").textContent = total ? (shown === total ? fmtNum(total) + " items" : `${fmtNum(shown)} of ${fmtNum(total)} items shown`) : "";
  $("hEmpty").hidden = total > 0;
}
let histCountTimer = 0;
function acceptFlow(f) {
  hist.lastId = Math.max(hist.lastId, f.id);
  app.flows.set(f.id, f);
  let cleared = 0;
  try { cleared = Number(sessionStorage.getItem("clearedBefore") || 0); } catch {}
  if (f.id <= cleared) return;
  const wrap = $("hWrap");
  const atBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 30;
  const tr = histTable.add(f);
  if (!tr.hidden && atBottom && histTable.key === "id" && histTable.dir === "asc") wrap.scrollTop = wrap.scrollHeight;
  clearTimeout(histCountTimer);
  histCountTimer = setTimeout(histCount, 80);
  emit("flowAdded", f);
}

async function showHistDetail(id) {
  const info = $("hInfo");
  let d;
  try { d = await loadFlow(id); } catch (err) { info.textContent = err.message; histPair.req.set(null); histPair.resp.set(null); return; }
  if (histTable.selected !== id) return;
  hist.detail = d;
  renderHistDetail();
}
function renderHistDetail() {
  const d = hist.detail, info = $("hInfo");
  info.textContent = "";
  const item = (label, value, cls) => info.append(h("span", { class: cls }, label + " ", h("b", {}, value)));
  item("#", d.id);
  item("", targetURL(d));
  if (d.status) item("Status", d.status);
  item("Time", d.ms + " ms");
  if (d.truncated) item("", "body truncated at the capture limit");
  if (d.note) item("Note:", d.note);
  if (d.error) item("Error:", d.error, "err");
  info.append(h("span", { class: "spacer" }),
    d.method !== "CONNECT" ? h("button", { class: "btn ask", title: `Talk to ${aiName()} about this request (Ctrl+J)`, onclick: () => askAboutFlow(d.id) }, "Ask " + aiName()) : null);
  if (d.edited) {
    info.append(
      h("button", { class: "btn" + (hist.showOriginal ? " on" : ""), onclick: () => { hist.showOriginal = true; renderHistDetail(); } }, "Original"),
      h("button", { class: "btn" + (!hist.showOriginal ? " on" : ""), onclick: () => { hist.showOriginal = false; renderHistDetail(); } }, "Edited"));
  }
  const orig = hist.showOriginal && d.edited;
  const req = orig && d.originalRequest ? d.originalRequest : d.request;
  const resp = orig && d.originalResponse ? d.originalResponse : d.response;
  histPair.req.set(b64ToBytes(req), null, "No request recorded.");
  histPair.resp.set(b64ToBytes(resp), orig ? null : (d.responseDecoded ? b64ToBytes(d.responseDecoded) : null),
    d.method === "CONNECT" ? "The tunnel was not decrypted." : "No response recorded.");
}

$("hFilter").addEventListener("input", (e) => { hist.filter = e.target.value.trim().toLowerCase(); histTable.refilter(); histCount(); });
for (const [id, key] of [["hScopeOnly", "scopeOnly"], ["hHideNoise", "hideNoise"], ["hHideStatic", "hideStatic"]]) {
  $(id).checked = hist[key];
  $(id).addEventListener("change", (e) => {
    hist[key] = e.target.checked; store.set("h." + key, hist[key]); histTable.refilter(); histCount();
    if (key === "scopeOnly" && hist.scopeOnly && !app.scope.length) toast("The scope is empty: add hosts in Target → Scope, or right-click an item → Add to scope.");
  });
}
$("hClear").addEventListener("click", () => {
  histTable.clear(); hist.detail = null;
  histPair.req.set(null); histPair.resp.set(null);
  $("hInfo").textContent = "";
  try { sessionStorage.setItem("clearedBefore", String(hist.lastId)); } catch {}
  histCount();
});
on("scopeChanged", async () => {
  const list = await getJSON("/api/flows");
  for (const s of list) { const f = app.flows.get(s.id); if (f) f.inScope = s.inScope; }
  histTable.refilter(); histCount();
});

// ═════════════ Intercept ═════════════
const ic = { state: { requests: false, responses: false, skipStatic: true, pending: [] }, current: null, item: null };
const icEditor = new Viewer($("icEditor"), { title: "Message", editable: true });
const icButtons = ["icForward", "icDrop", "icRep", "icInt", "icAsk"];

function renderIntercept() {
  const s = ic.state, n = s.pending.length;
  const t = $("icToggle");
  t.textContent = s.requests ? "Intercept is on" : "Intercept is off";
  t.classList.toggle("on", s.requests);
  $("icResponses").checked = s.responses;
  $("icSkipStatic").checked = s.skipStatic;
  for (const el of $$(".setReq")) el.checked = s.requests;
  for (const el of $$(".setResp")) el.checked = s.responses;
  for (const el of $$(".setStatic")) el.checked = s.skipStatic;
  $("icCountTab").textContent = n ? n : "";
  $("proxyCount").textContent = n ? n : "";
  $("icAll").disabled = !n;

  const tbody = $("icTable").tBodies[0];
  tbody.textContent = "";
  for (const it of s.pending) {
    const req = it.kind === "request";
    tbody.append(h("tr", { class: it.id === ic.current ? "sel" : "", onclick: () => openHeld(it.id) },
      h("td", { class: "dim" }, fmtTime(it.time)), h("td", {}, req ? "HTTP request" : "HTTP response"),
      h("td", {}, req ? "→ To server" : "← To client"), h("td", {}, it.method), h("td", { title: it.url }, it.url),
      h("td", {}, it.status || ""), h("td", { class: "r" }, fmtNum(it.length))));
  }
  if (ic.current !== null && !s.pending.some((it) => it.id === ic.current)) closeHeld();
  if (ic.current === null && n) openHeld(s.pending[0].id);
  if (ic.current === null) {
    $("icInfo").textContent = s.requests || s.responses
      ? "Waiting for messages… In-scope requests are held here before they are sent."
      : "Intercept is off. Turn it on to hold requests before they are sent, then edit, forward or drop them.";
  }
}
function closeHeld() {
  ic.current = null; ic.item = null;
  icEditor.set(null);
  for (const b of icButtons) $(b).disabled = true;
}
let icOpening = null;
async function openHeld(id) {
  if (ic.current === id || icOpening === id) return;
  if (icEditor.dirty && ic.current !== null) { toast("Forward or drop the edited message first."); return; }
  icOpening = id;
  try {
    const it = await getJSON("/api/intercept/" + id);
    ic.current = id; ic.item = it;
    icEditor.set(b64ToBytes(it.raw));
    for (const b of icButtons) $(b).disabled = false;
    $("icRep").disabled = $("icInt").disabled = it.kind !== "request";
    const info = $("icInfo");
    info.textContent = "";
    const u = new URL(it.url);
    info.append(h("span", {}, it.kind === "request" ? "Request to " : "Response from ", h("b", {}, it.kind === "request" ? u.origin : it.url)));
    if (it.binary) info.append(h("span", { class: "err" }, "The body is not text; editing it may corrupt it."));
  } catch { /* already decided */ } finally { icOpening = null; }
  renderIntercept();
}
async function decideHeld(action) {
  if (ic.current === null) return;
  const id = ic.current, body = { action };
  if (action === "forward" && icEditor.dirty) body.raw = icEditor.getText();
  try { await api("POST", "/api/intercept/" + id, body); if (ic.current === id) { icEditor.dirty = false; closeHeld(); } }
  catch (err) { toast(err.message, true); }
}
async function configureIntercept(patch) {
  const s = ic.state;
  try { ic.state = await api("PUT", "/api/intercept", { requests: s.requests, responses: s.responses, skipStatic: s.skipStatic, ...patch }); renderIntercept(); }
  catch (err) { toast(err.message, true); }
}
$("icToggle").addEventListener("click", () => {
  const on = !ic.state.requests;
  configureIntercept({ requests: on });
  if (on && !app.scope.length) toast("The scope is empty, so every page the browser loads will be held. Add your target in Target → Scope.");
});
$("icResponses").addEventListener("change", (e) => configureIntercept({ responses: e.target.checked }));
$("icSkipStatic").addEventListener("change", (e) => configureIntercept({ skipStatic: e.target.checked }));
for (const el of $$(".setReq")) el.addEventListener("change", (e) => configureIntercept({ requests: e.target.checked }));
for (const el of $$(".setResp")) el.addEventListener("change", (e) => configureIntercept({ responses: e.target.checked }));
for (const el of $$(".setStatic")) el.addEventListener("change", (e) => configureIntercept({ skipStatic: e.target.checked }));
$("icForward").addEventListener("click", () => decideHeld("forward"));
$("icDrop").addEventListener("click", () => decideHeld("drop"));
$("icAll").addEventListener("click", async () => {
  for (const it of [...ic.state.pending]) { try { await api("POST", "/api/intercept/" + it.id, { action: "forward" }); } catch {} }
});
function heldTarget() { const u = new URL(ic.item.url); return u.origin; }
$("icRep").addEventListener("click", () => ic.item && sendToRepeater(heldTarget(), icEditor.getText()));
$("icAsk").addEventListener("click", () => {
  if (!ic.item) return;
  const req = ic.item.kind === "request";
  askClaude({
    key: "held:" + ic.item.id, title: `Intercepted ${ic.item.kind} · ${ic.item.method} ${ic.item.url}`, target: heldTarget(),
    note: req ? "A request held in Intercept, not sent yet" : "A response held in Intercept, not delivered yet",
    request: req ? icEditor.getText() : "(not shown; the request was " + ic.item.method + " " + ic.item.url + ")",
    response: req ? "" : icEditor.getText(),
  });
});
$("icInt").addEventListener("click", () => ic.item && sendToIntruder(heldTarget(), icEditor.getText()));
$("icEditor").addEventListener("contextmenu", (e) => {
  if (!ic.item) return;
  const sel = icEditor.selection();
  showMenu(e, [
    { label: "Forward", key: "Ctrl+F", action: () => decideHeld("forward") },
    { label: "Drop", key: "Ctrl+D", action: () => decideHeld("drop") },
    "-",
    { label: "Send to Repeater", key: "Ctrl+R", disabled: ic.item.kind !== "request", action: () => sendToRepeater(heldTarget(), icEditor.getText()) },
    { label: "Send to Intruder", key: "Ctrl+I", disabled: ic.item.kind !== "request", action: () => sendToIntruder(heldTarget(), icEditor.getText()) },
    { label: sel ? "Send selection to Decoder" : "Send to Decoder", action: () => sendToDecoder(sel || icEditor.getText()) },
  ]);
});
let heldNoticeAt = 0;
on("intercept", (state) => {
  const before = ic.state.pending.length;
  ic.state = state;
  renderIntercept();
  const away = app.tab !== "proxy" || app.sub.proxy !== "p-intercept";
  if (away && state.pending.length > before && Date.now() - heldNoticeAt > 5000) {
    heldNoticeAt = Date.now();
    toast("Intercept: a message is waiting for you in Proxy → Intercept.");
  }
});
on("open", () => getJSON("/api/intercept").then((s) => { ic.state = s; renderIntercept(); }));

// ═════════════ WebSockets history ═════════════
let wsFilterText = "";
const wsTable = new SortTable($("wsTable"), {
  render: (m) => h("tr", {},
    h("td", { class: "num" }, m.id), h("td", { title: m.url }, m.url),
    h("td", {}, m.toServer ? "→ To server" : "← To client"),
    h("td", { class: "r" }, fmtNum(m.length)), h("td", { class: "dim" }, fmtTime(m.time)),
    h("td", { title: m.preview }, m.preview)),
  filter: (m) => !wsFilterText || (m.url + " " + m.preview).toLowerCase().includes(wsFilterText),
  onSelect: async (m) => {
    const full = await getJSON("/api/ws/" + m.id).catch((err) => { toast(err.message, true); return null; });
    if (!full || wsTable.selected !== m.id) return;
    $("wsInfo").textContent = "";
    $("wsInfo").append(h("span", {}, "# ", h("b", {}, m.id)), h("span", {}, m.toServer ? "To server" : "To client"),
      h("span", {}, h("b", {}, m.url)), h("span", {}, "Handshake #" + m.flowId),
      full.truncated ? h("span", {}, `showing ${fmtNum(1 << 20)} of ${fmtNum(full.length)} bytes`) : null);
    wsViewer.set(b64ToBytes(full.data), null, "Empty message.");
  },
  onMenu: (e, m) => showMenu(e, [
    { label: "Send to Decoder", action: async () => { const full = await getJSON("/api/ws/" + m.id); sendToDecoder(bytesToText(b64ToBytes(full.data))); } },
    { label: "Copy URL", action: () => copyText(m.url, "URL") },
  ]),
});
const wsViewer = new Viewer($("wsViewer"), { title: "Message", http: false });
hsplit($("p-ws").querySelector(".hsplit"), $("p-ws"));
function wsCount() { $("wsCount").textContent = wsTable.rows.size ? fmtNum(wsTable.rows.size) + " messages" : ""; $("wsEmpty").hidden = wsTable.rows.size > 0; }
on("ws", (m) => { wsTable.add(m); wsCount(); });
$("wsFilter").addEventListener("input", (e) => { wsFilterText = e.target.value.trim().toLowerCase(); wsTable.refilter(); });

// ═════════════ Match and replace ═════════════
const RULE_TYPES = {
  request_header: "Request header", request_body: "Request body", request_first_line: "Request first line",
  response_header: "Response header", response_body: "Response body", response_first_line: "Response first line",
};
let rules = [], ruleSel = -1, ruleEditing = -1;
function renderRules() {
  const tbody = $("rTable").tBodies[0];
  tbody.textContent = "";
  rules.forEach((r, i) => {
    const cb = h("input", { type: "checkbox", onclick: (e) => e.stopPropagation(), onchange: (e) => { rules[i].enabled = e.target.checked; saveRules(); } });
    cb.checked = r.enabled;
    tbody.append(h("tr", { class: i === ruleSel ? "sel" : "", onclick: () => { ruleSel = i; renderRules(); }, ondblclick: () => editRule(i) },
      h("td", { class: "c" }, cb), h("td", {}, RULE_TYPES[r.type] || r.type),
      h("td", { title: r.match }, r.match || h("span", { class: "muted" }, "(add)")), h("td", { title: r.replace }, r.replace || h("span", { class: "muted" }, "(remove)")),
      h("td", {}, r.regex ? "Regex" : "Literal"), h("td", {}, r.comment || "")));
  });
  for (const id of ["rEdit", "rRemove"]) $(id).disabled = ruleSel < 0;
  $("rUp").disabled = ruleSel <= 0;
  $("rDown").disabled = ruleSel < 0 || ruleSel >= rules.length - 1;
}
async function saveRules() {
  try { rules = await api("PUT", "/api/rules", rules); renderRules(); }
  catch (err) { toast(err.message, true); rules = await getJSON("/api/rules"); renderRules(); }
}
function editRule(i) {
  ruleEditing = i;
  const r = i >= 0 ? rules[i] : { type: "request_header", match: "", replace: "", regex: false, comment: "" };
  $("ruleTitle").textContent = i >= 0 ? "Edit match/replace rule" : "Add match/replace rule";
  $("ruleType").value = r.type; $("ruleMatch").value = r.match; $("ruleReplace").value = r.replace;
  $("ruleRegex").checked = r.regex; $("ruleComment").value = r.comment || "";
  $("ruleDialog").showModal();
}
$("rAdd").addEventListener("click", () => editRule(-1));
$("rEdit").addEventListener("click", () => ruleSel >= 0 && editRule(ruleSel));
$("rRemove").addEventListener("click", () => { if (ruleSel < 0) return; rules.splice(ruleSel, 1); ruleSel = -1; saveRules(); });
$("rUp").addEventListener("click", () => { if (ruleSel <= 0) return; [rules[ruleSel - 1], rules[ruleSel]] = [rules[ruleSel], rules[ruleSel - 1]]; ruleSel--; saveRules(); });
$("rDown").addEventListener("click", () => { if (ruleSel >= rules.length - 1) return; [rules[ruleSel + 1], rules[ruleSel]] = [rules[ruleSel], rules[ruleSel + 1]]; ruleSel++; saveRules(); });
$("ruleCancel").addEventListener("click", () => $("ruleDialog").close());
$("ruleOk").addEventListener("click", async () => {
  const r = { enabled: ruleEditing >= 0 ? rules[ruleEditing].enabled : true, type: $("ruleType").value, match: $("ruleMatch").value,
    replace: $("ruleReplace").value, regex: $("ruleRegex").checked, comment: $("ruleComment").value };
  const before = rules.slice();
  if (ruleEditing >= 0) rules[ruleEditing] = r; else { rules.push(r); ruleSel = rules.length - 1; }
  try { rules = await api("PUT", "/api/rules", rules); $("ruleDialog").close(); renderRules(); }
  catch (err) { rules = before; toast(err.message, true); }
});

// ═════════════ Keyboard ═════════════
addEventListener("keydown", (e) => {
  if (app.tab !== "proxy") return;
  const mod = e.ctrlKey || e.metaKey;
  const sub = app.sub.proxy;
  if (sub === "p-intercept" && mod && !e.shiftKey) {
    const k = e.key.toLowerCase();
    if (k === "f") { e.preventDefault(); decideHeld("forward"); }
    if (k === "d") { e.preventDefault(); decideHeld("drop"); }
    if (k === "r" && ic.item?.kind === "request") { e.preventDefault(); sendToRepeater(heldTarget(), icEditor.getText()); }
    if (k === "i" && ic.item?.kind === "request") { e.preventDefault(); sendToIntruder(heldTarget(), icEditor.getText()); }
    return;
  }
  if (sub === "p-history") {
    const d = hist.detail;
    if (mod && (e.key === "r" || e.key === "R") && d && d.method !== "CONNECT") { e.preventDefault(); sendToRepeater(targetURL(d), bytesToText(b64ToBytes(d.request))); return; }
    if (mod && (e.key === "i" || e.key === "I") && d && d.method !== "CONNECT") { e.preventDefault(); sendToIntruder(targetURL(d), bytesToText(b64ToBytes(d.request))); return; }
    if (mod && (e.key === "j" || e.key === "J") && d && d.method !== "CONNECT") { e.preventDefault(); askAboutFlow(d.id); return; }
    if (["INPUT", "TEXTAREA", "SELECT"].includes(e.target.tagName)) return;
    if (e.key === "ArrowDown") { e.preventDefault(); histTable.step(1); }
    if (e.key === "ArrowUp") { e.preventDefault(); histTable.step(-1); }
  }
});

async function initProxy() {
  const [flows, state, rl, ws] = await Promise.all([getJSON("/api/flows"), getJSON("/api/intercept"), getJSON("/api/rules"), getJSON("/api/ws")]);
  flows.forEach(acceptFlow);
  histCount();
  $("hWrap").scrollTop = $("hWrap").scrollHeight;
  ic.state = state; renderIntercept();
  rules = rl; renderRules();
  ws.forEach((m) => wsTable.add(m)); wsCount();
}
on("flow", acceptFlow);
