"use strict";
// Repeater: numbered tabs, each with a target, an editable request and the
// history of what it sent.

const rep = {
  tabs: store.get("rep.tabs", []), // [{id, target, raw}]
  active: store.get("rep.active", null),
  runs: new Map(),                  // tab id -> {list: [{target, raw, d|error}], pos}
  abort: null,
};
rep.next = rep.tabs.reduce((m, t) => Math.max(m, t.id), 0) + 1;
const repPair = makePair($("repPair"), { req: { editable: true } });

function repSave() {
  store.set("rep.tabs", rep.tabs.map(({ id, target, raw }) => ({ id, target, raw })));
  store.set("rep.active", rep.active);
}
const repTab = () => rep.tabs.find((t) => t.id === rep.active);

function sendToRepeater(target, raw) {
  const t = { id: rep.next++, target, raw };
  rep.tabs.push(t);
  rep.active = t.id;
  repSave();
  flash("repeater");
  renderRepeater();
  toast("Sent to Repeater (tab " + t.id + ").");
}

function renderRepeater() {
  if (!rep.tabs.length) rep.tabs.push({ id: rep.next++, target: "https://example.com", raw: "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: lightproxy\r\nAccept: */*\r\n\r\n" });
  if (!repTab()) rep.active = rep.tabs[rep.tabs.length - 1].id;
  const bar = $("repTabs");
  bar.textContent = "";
  for (const t of rep.tabs) {
    bar.append(h("button", { class: t.id === rep.active ? "active" : "", onclick: () => { rep.active = t.id; repSave(); renderRepeater(); } },
      String(t.id),
      h("span", { class: "x", title: "Close tab", onclick: (e) => {
        e.stopPropagation();
        rep.tabs = rep.tabs.filter((o) => o.id !== t.id); rep.runs.delete(t.id); repSave(); renderRepeater();
      } }, "×")));
  }
  bar.append(h("button", { title: "New tab", onclick: () => { const a = repTab(); sendToRepeater(a ? a.target : "https://example.com", a ? a.raw : ""); } }, "+"));
  const t = repTab();
  $("repTarget").value = t.target;
  repPair.req.setText(t.raw);
  showRun();
}

function showRun() {
  const t = repTab(), run = rep.runs.get(t.id);
  const cur = run && run.list[run.pos];
  $("repPrev").disabled = !run || run.pos <= 0;
  $("repNext").disabled = !run || run.pos >= run.list.length - 1;
  const status = $("repStatus");
  if (!cur) { repPair.resp.set(null, null, "Click Send (Ctrl+Space) to send the request."); status.textContent = "Ready"; return; }
  if (cur.pending) { status.textContent = "Sending…"; repPair.resp.set(null, null, "Waiting for the response…"); return; }
  if (cur.error) { status.textContent = "Error"; repPair.resp.set(null, null, cur.error); return; }
  const d = cur.d;
  repPair.resp.set(b64ToBytes(d.response), d.responseDecoded ? b64ToBytes(d.responseDecoded) : null, d.error || "No response.");
  status.textContent = (d.error ? "Error: " + d.error : "Done") + " · " + fmtNum(d.respSize) + " bytes · " + fmtNum(d.ms) + " millis" +
    (run.list.length > 1 ? ` · request ${run.pos + 1} of ${run.list.length}` : "");
}

async function repSend() {
  const t = repTab();
  if (!t || rep.abort) return;
  t.raw = repPair.req.getText();
  t.target = $("repTarget").value.trim();
  repSave();
  const run = rep.runs.get(t.id) || { list: [], pos: -1 };
  rep.runs.set(t.id, run);
  const entry = { target: t.target, raw: t.raw, pending: true };
  run.list.push(entry); run.pos = run.list.length - 1;
  showRun();
  rep.abort = new AbortController();
  $("repSend").disabled = true; $("repCancel").disabled = false;
  try {
    entry.d = await api("POST", "/api/repeater", { target: t.target, raw: t.raw }, rep.abort.signal);
  } catch (err) {
    entry.error = err.name === "AbortError" ? "Cancelled." : err.message;
  } finally {
    entry.pending = false;
    rep.abort = null;
    $("repSend").disabled = false; $("repCancel").disabled = true;
    if (rep.active === t.id) showRun();
  }
}
$("repSend").addEventListener("click", repSend);
$("repAsk").addEventListener("click", () => {
  const t = repTab(), run = rep.runs.get(t.id), cur = run && run.list[run.pos];
  const d = cur && cur.d;
  askClaude({
    key: "rep:" + t.id, title: `Repeater tab ${t.id} · ${t.target}`, target: t.target, note: "Repeater tab " + t.id,
    request: repPair.req.getText(), response: d ? messageText(d.response, d.responseDecoded) : "",
  });
});
$("repCancel").addEventListener("click", () => rep.abort?.abort());
function repStep(dir) {
  const t = repTab(), run = rep.runs.get(t.id);
  if (!run) return;
  run.pos = Math.min(Math.max(run.pos + dir, 0), run.list.length - 1);
  const e = run.list[run.pos];
  t.target = e.target; t.raw = e.raw;
  $("repTarget").value = e.target; repPair.req.setText(e.raw);
  repSave(); showRun();
}
$("repPrev").addEventListener("click", () => repStep(-1));
$("repNext").addEventListener("click", () => repStep(1));
$("repTarget").addEventListener("input", (e) => { const t = repTab(); if (t) { t.target = e.target.value.trim(); repSave(); } });
repPair.req.onInput = () => { const t = repTab(); if (t) { t.raw = repPair.req.getText(); repSave(); } };

$("repPair").addEventListener("contextmenu", (e) => {
  const inReq = repPair.req.el.contains(e.target);
  const v = inReq ? repPair.req : repPair.resp;
  const sel = v.selection();
  const t = repTab();
  showMenu(e, [
    { label: "Send", key: "Ctrl+Space", disabled: !inReq, action: repSend },
    { label: "Send to Intruder", key: "Ctrl+I", disabled: !inReq, action: () => sendToIntruder(t.target, repPair.req.getText()) },
    { label: sel ? "Send selection to Decoder" : "Send to Decoder", action: () => sendToDecoder(sel || v.getText()) },
    "-",
    { label: "Copy as curl command", disabled: !inReq, action: () => copyText(toCurl(repPair.req.getText(), t.target), "curl command") },
  ]);
});
addEventListener("keydown", (e) => {
  if (app.tab !== "repeater" || !(e.ctrlKey || e.metaKey)) return;
  if (e.key === " " || e.key === "Enter") { e.preventDefault(); repSend(); }
  if (e.key === "i" || e.key === "I") { e.preventDefault(); const t = repTab(); sendToIntruder(t.target, repPair.req.getText()); }
});
on("tabShown", (tab) => { if (tab === "repeater") repPair.req.focus(); });
