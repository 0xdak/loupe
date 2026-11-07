"use strict";
// Ask Claude: a side panel to talk to Claude about HTTP exchanges. Each
// exchange has its own conversation; all of them are listed under "Chats"
// and kept in this browser across reloads.

const ask = {
  chats: new Map(), // key -> {key, ctx, history: [{role, text, label}], updated, abort}
  key: null,
  view: "chat",     // "chat" or "list"
  lang: store.get("ask.lang", "auto"),
};
const CHIPS = [
  ["Explain this request", "Explain what this request does, what the server returned, and anything notable about it."],
  ["Find security issues", "Look for security issues or interesting attack surface in this exchange (parameters, headers, cookies, tokens, response contents). List the most promising ones first, each with how to test it."],
  ["Suggest test requests", "Suggest a few modified requests worth sending to test this endpoint. Give each as a complete raw HTTP request."],
  ["Explain the response", "Explain the response: status, important headers, cookies and what the body contains."],
];

// ── Persistence: the most recent chats are kept in localStorage ──
const ASK_KEEP = 60, ASK_CTX_MAX = 120 * 1024;
function saveChats() {
  const list = [...ask.chats.values()].filter((c) => c.history.length)
    .sort((a, b) => b.updated - a.updated).slice(0, ASK_KEEP)
    .map((c) => ({
      key: c.key, updated: c.updated,
      ctx: { ...c.ctx, request: (c.ctx.request || "").slice(0, ASK_CTX_MAX), response: (c.ctx.response || "").slice(0, ASK_CTX_MAX) },
      history: c.history.filter((m) => !m.pending || m.text).map(({ role, text, label, error }) => ({ role, text, label, error })),
    }));
  // If the browser's storage is full, keep fewer chats rather than none.
  for (let n = list.length; n >= 0; n = n ? Math.floor(n / 2) : -1) {
    try { localStorage.setItem("lp.ask.chats", JSON.stringify(list.slice(0, n))); return; } catch {}
  }
}
function loadChats() {
  for (const c of store.get("ask.chats", [])) ask.chats.set(c.key, { ...c, abort: null });
}
loadChats();

// aiName is the active model's short label (e.g. "Claude", "Ollama · qwen2.5").
function aiName() { return (app.info && app.info.assistantName) || "Claude"; }
// applyAiName updates the fixed labels once /api/info has loaded.
function applyAiName() {
  const n = aiName();
  const top = $("askTop");
  if (top && top.firstChild) { top.firstChild.nodeValue = "✦ " + n; top.title = n + " conversations"; }
  const title = $("asTitle"); if (title) title.textContent = "Ask " + n;
  for (const id of ["icAsk", "repAsk"]) {
    const b = $(id);
    if (b) { b.textContent = "Ask " + n; b.title = "Talk to " + n + " about this message"; }
  }
}

// messageText turns base64 message bytes into text for Claude, preferring the
// decoded (decompressed) version and replacing binary bodies with a note.
function messageText(b64, decodedB64) {
  if (!b64) return "";
  const bytes = b64ToBytes(decodedB64 || b64);
  if (isUTF8(bytes)) return bytesToText(bytes);
  const text = latin1(bytes);
  const [head, body] = splitMessage(text);
  return head + `[binary body, ${fmtNum(textToBytes(body).length)} bytes, not shown]`;
}

// askClaude opens the conversation of an exchange, creating it when new.
// ctx: {key, title, target, request, response, note}
function askClaude(ctx, question) {
  const chat = ask.chats.get(ctx.key);
  if (!chat) ask.chats.set(ctx.key, { key: ctx.key, ctx, history: [], updated: Date.now(), abort: null });
  else chat.ctx = ctx; // keep the latest request/response text
  openChat(ctx.key);
  if (question) sendAsk(question);
}
function openChat(key) {
  ask.key = key; ask.view = "chat";
  $("assist").hidden = false;
  renderAsk();
  $("asInput").focus();
}
async function askAboutFlow(id) {
  const d = await loadFlow(id);
  askClaude({
    key: "flow:" + id, title: `#${d.id} ${d.method} ${d.url}`, target: targetURL(d), note: "Proxy history #" + d.id,
    request: messageText(d.request), response: messageText(d.response, d.responseDecoded),
  });
}
function chatCount() { return [...ask.chats.values()].filter((c) => c.history.length).length; }
function updateChatsButton() {
  const n = chatCount(), busy = [...ask.chats.values()].some((c) => c.abort);
  $("asList").textContent = (ask.view === "list" ? "← Back" : "☰ Chats") + (ask.view === "list" ? "" : ` (${n})`);
  $("asList").classList.toggle("on", busy && ask.view !== "list");
  const top = $("askTop");
  if (top) { top.querySelector(".count").textContent = n ? n : ""; top.classList.toggle("alert", busy); }
}

function renderAsk() {
  updateChatsButton();
  const list = ask.view === "list";
  $("asChips").hidden = $("asInputRow").hidden = list;
  if (list) return renderChatList();
  const chat = ask.chats.get(ask.key);
  $("asCtx").textContent = chat ? chat.ctx.title : "";
  $("asCtx").title = chat ? chat.ctx.title : "";
  const box = $("asMsgs");
  const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
  box.textContent = "";
  if (!app.info.assistant) {
    box.append(h("div", { class: "as-note err" }, app.info.assistantError || `Ask ${aiName()} is not available.`));
  } else if (!chat) {
    box.append(h("div", { class: "as-note" }, `Open a request and click Ask ${aiName()}, or pick a conversation from Chats.`));
  } else if (!chat.history.length) {
    box.append(h("div", { class: "as-note" },
      `Ask anything about this request and its response. ${aiName()} sees the request and response shown here, and cannot run tools or change anything.`));
  }
  if (chat) for (const m of chat.history) box.append(bubble(m, chat.ctx));
  const chips = $("asChips");
  chips.textContent = "";
  const busy = !!chat?.abort;
  for (const [label, q] of CHIPS) chips.append(h("button", { class: "chip", disabled: busy || !chat || !app.info.assistant, onclick: () => sendAsk(q, label) }, label));
  $("asSend").textContent = busy ? "Stop" : "Send";
  if (stick || busy) box.scrollTop = box.scrollHeight;
}

function renderChatList() {
  $("asCtx").textContent = chatCount() + " conversation(s)";
  const box = $("asMsgs");
  box.textContent = "";
  const chats = [...ask.chats.values()].filter((c) => c.history.length || c.abort).sort((a, b) => b.updated - a.updated);
  if (!chats.length) { box.append(h("div", { class: "as-note" }, `No conversations yet. Open a request and click Ask ${aiName()}.`)); return; }
  for (const c of chats) {
    const last = [...c.history].reverse().find((m) => m.role === "assistant" && m.text) || c.history[c.history.length - 1];
    const snippet = last ? (last.label || last.text).replace(/```[\s\S]*?(```|$)/g, "[code]").replace(/\s+/g, " ").slice(0, 140) : "";
    const questions = c.history.filter((m) => m.role === "user").length;
    box.append(h("div", { class: "as-item" + (c.key === ask.key ? " sel" : ""), onclick: () => openChat(c.key), title: c.ctx.title },
      h("div", { class: "as-item-top" },
        h("b", {}, c.ctx.title),
        c.abort ? h("span", { class: "as-busy" }, "answering…") : null,
        h("span", { class: "muted small" }, new Date(c.updated).toLocaleString("en-GB", { hour12: false, month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })),
        h("button", { class: "as-del", title: "Delete this conversation", onclick: (e) => {
          e.stopPropagation(); c.abort?.abort(); ask.chats.delete(c.key); saveChats(); renderAsk();
        } }, "×")),
      h("div", { class: "muted small" }, `${questions} question${questions === 1 ? "" : "s"} · ${c.ctx.note || ""}`),
      h("div", { class: "as-snippet" }, snippet)));
  }
}

function bubble(m, ctx) {
  const el = h("div", { class: "as-msg " + m.role });
  if (m.role === "user") el.append(m.label || m.text);
  else {
    el.append(renderMarkdown(m.text, ctx));
    if (m.pending) el.append(h("span", { class: "as-cursor" }, "▍"));
    if (m.error) el.append(h("div", { class: "err" }, m.error));
  }
  return el;
}

function langSuffix() {
  const l = ask.lang === "auto" ? (navigator.language || "en").slice(0, 2) : ask.lang;
  return l === "tr" ? "\n\n(Türkçe cevap ver.)" : "";
}

// sendAsk asks a question in the open conversation. Conversations stream
// independently, so another one can be opened and used meanwhile.
async function sendAsk(text, label) {
  const chat = ask.chats.get(ask.key);
  if (!chat || chat.abort || !text.trim() || !app.info.assistant) return;
  const question = text.trim() + langSuffix();
  chat.history.push({ role: "user", text: question, label: label || text.trim() });
  const answer = { role: "assistant", text: "", pending: true };
  const history = chat.history.map(({ role, text }) => ({ role, text }));
  chat.history.push(answer);
  chat.updated = Date.now();
  $("asInput").value = "";
  chat.abort = new AbortController();
  saveChats();
  renderAsk();
  const c = chat.ctx;
  const visible = () => !$("assist").hidden && (ask.view === "list" || ask.key === chat.key);
  try {
    const res = await fetch("/api/assist", {
      method: "POST", signal: chat.abort.signal,
      headers: { "X-Lightproxy": "1", "Content-Type": "application/json" },
      body: JSON.stringify({ exchange: { target: c.target, request: c.request, response: c.response, note: c.note }, history }),
    });
    if (!res.ok) throw new Error((await res.text()).trim());
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "", last = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        if (!line) continue;
        const ev = JSON.parse(line);
        if (ev.text) answer.text += ev.text;
        if (ev.error) answer.error = ev.error;
      }
      if (Date.now() - last > 80 && visible()) { last = Date.now(); renderAsk(); }
    }
  } catch (err) {
    answer.error = err.name === "AbortError" ? "Stopped." : err.message;
  } finally {
    answer.pending = false;
    chat.abort = null;
    chat.updated = Date.now();
    saveChats();
    if (visible()) renderAsk(); else updateChatsButton();
    if (!visible() && !answer.error) toast(aiName() + " answered: " + chat.ctx.title.slice(0, 80));
  }
}

// renderMarkdown renders the subset of Markdown Claude uses, safely (no HTML).
function renderMarkdown(text, ctx) {
  const frag = document.createDocumentFragment();
  const re = /```([\w-]*)[^\n]*\n?([\s\S]*?)(?:```|$)/g;
  let pos = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > pos) frag.append(renderProse(text.slice(pos, m.index)));
    frag.append(codeBlock(m[2].replace(/\n$/, ""), m[1], ctx));
    pos = re.lastIndex;
    if (m[0].length === 0) break;
  }
  if (pos < text.length) frag.append(renderProse(text.slice(pos)));
  return frag;
}
function codeBlock(code, lang, ctx) {
  const isRequest = /^[A-Z]+ \S+ HTTP\/[\d.]+/.test(code.trimStart());
  const raw = () => code.trimStart().replace(/\r?\n/g, "\r\n") + (/\r?\n\r?\n/.test(code) ? "" : "\r\n\r\n");
  const held = isRequest && ctx.key.startsWith("held:") && ctx.response === "";
  const tools = h("div", { class: "as-tools" },
    h("span", { class: "muted" }, lang || (isRequest ? "http" : "")),
    h("span", { class: "spacer" }),
    isRequest ? h("button", { class: "go", title: `Send this request through the proxy and show ${aiName()} the response here`,
      onclick: (e) => sendAndReply(ctx, raw(), e.currentTarget) }, "Send & show response") : null,
    held ? h("button", { class: "go", title: "Forward the intercepted request with this edit instead of the original",
      onclick: () => forwardHeldEdit(ctx, raw()) }, "Forward this instead") : null,
    isRequest ? h("button", { onclick: () => sendToRepeater(ctx.target, raw()) }, "Repeater") : null,
    isRequest ? h("button", { onclick: () => sendToIntruder(ctx.target, raw()) }, "Intruder") : null,
    h("button", { onclick: () => copyText(code, "Code") }, "Copy"));
  return h("div", { class: "as-code" }, tools, h("pre", {}, code));
}

// sendAndReply sends one request Claude proposed — a human click per send —
// and feeds the real response back into the conversation so Claude continues.
async function sendAndReply(ctx, raw, btn) {
  const chat = ask.chats.get(ctx.key);
  if (!chat || chat.abort) return;
  btn.disabled = true;
  let d;
  try {
    d = await api("POST", "/api/repeater", { target: ctx.target, raw });
  } catch (err) {
    btn.disabled = false;
    toast("Could not send: " + err.message, true);
    return;
  }
  // The latest response becomes the exchange Claude reasons about next.
  chat.ctx = { ...ctx, request: messageText(d.request), response: messageText(d.response, d.responseDecoded) };
  const respText = messageText(d.response, d.responseDecoded) || "(no response body)";
  const label = `Sent the request → ${d.error ? "error: " + d.error : d.status} (history #${d.id})`;
  sendAsk(`I sent that request through the proxy. The response (history #${d.id}) was:\n\n` +
    "```http\n" + respText.slice(0, 20000) + "\n```\n\nWhat does this tell us, and what should we try next?", label);
}

async function forwardHeldEdit(ctx, raw) {
  const id = Number(ctx.key.slice("held:".length));
  try {
    await api("POST", "/api/intercept/" + id, { action: "forward", raw });
    toast(`Forwarded ${aiName()}'s version of the held request.`);
  } catch (err) {
    toast("Could not forward: " + err.message, true);
  }
}
function renderProse(text) {
  const frag = document.createDocumentFragment();
  for (const line of text.replace(/^\n+|\n+$/g, "").split("\n")) {
    const hm = line.match(/^(#{1,4})\s+(.*)$/);
    if (hm) { frag.append(h("div", { class: "as-h" }, inline(hm[2]))); continue; }
    const li = line.match(/^(\s*)([-*]|\d+\.)\s+(.*)$/);
    if (li) { frag.append(h("div", { class: "as-li", style: `padding-left:${12 + li[1].length * 6}px` }, li[2].match(/\d/) ? li[2] + " " : "• ", inline(li[3]))); continue; }
    if (!line.trim()) { frag.append(h("div", { class: "as-gap" })); continue; }
    frag.append(h("div", {}, inline(line)));
  }
  return frag;
}
function inline(s) {
  const out = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*)/g;
  let pos = 0, m;
  while ((m = re.exec(s))) {
    if (m.index > pos) out.push(s.slice(pos, m.index));
    out.push(m[0].startsWith("`") ? h("code", {}, m[0].slice(1, -1)) : h("b", {}, m[0].slice(2, -2)));
    pos = re.lastIndex;
  }
  out.push(s.slice(pos));
  return out;
}

$("asSend").addEventListener("click", () => {
  const chat = ask.chats.get(ask.key);
  chat?.abort ? chat.abort.abort() : sendAsk($("asInput").value);
});
$("asInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendAsk($("asInput").value); }
});
$("asClose").addEventListener("click", () => { $("assist").hidden = true; });
$("asList").addEventListener("click", () => { ask.view = ask.view === "list" ? "chat" : "list"; renderAsk(); });
$("asNew").addEventListener("click", () => {
  const c = ask.chats.get(ask.key);
  if (c && !c.abort) { c.history = []; saveChats(); renderAsk(); }
});
$("askTop").addEventListener("click", () => {
  if (!$("assist").hidden) { $("assist").hidden = true; return; }
  ask.view = ask.key && ask.chats.has(ask.key) ? "chat" : "list";
  $("assist").hidden = false;
  renderAsk();
});
$("asLang").value = ask.lang;
$("asLang").addEventListener("change", (e) => { ask.lang = e.target.value; store.set("ask.lang", ask.lang); });
addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("assist").hidden && !document.querySelector("dialog[open]")) $("assist").hidden = true; });
updateChatsButton();

// ── AI provider & model picker ──
// Lets the provider (Claude / Ollama / OpenAI-compatible) and model be chosen
// in the interface instead of only by command-line flags. The choice is saved
// on the machine; the API key is never sent back to the browser.
const aiPick = { status: {}, discovery: {} };

async function openAiDialog() {
  if (!app.info || !app.info.aiConfigurable) {
    toast("This loupe build cannot change the AI model from the interface.", true);
    return;
  }
  try {
    const data = await getJSON("/api/ai");
    aiPick.status = data.status || {};
    aiPick.discovery = data.discovery || {};
  } catch (err) {
    toast("Could not load AI settings: " + err.message, true);
    return;
  }
  const st = aiPick.status;
  $("aiProvider").value = st.provider || "auto";
  $("aiModel").value = st.model || "";
  $("aiURL").value = st.url || "";
  $("aiKey").value = "";
  $("aiKey").placeholder = st.hasKey ? "•••• stored — leave blank to keep it" : "kept on this machine, never shown";
  renderAiForm();
  const d = $("aiDialog");
  if (!d.open) d.showModal();
}

function aiRow(labelId, inputId, show) {
  for (const id of [labelId, inputId]) { const el = $(id); if (el) el.hidden = !show; }
}

function renderAiForm() {
  const p = $("aiProvider").value;
  const disc = aiPick.discovery || {};
  const dl = $("aiModelList");
  dl.textContent = "";
  aiRow("aiModelLabel", "aiModel", p !== "auto");
  aiRow("aiURLLabel", "aiURL", p === "ollama" || p === "openai");
  aiRow("aiKeyLabel", "aiKey", p === "openai");
  let hint = "";
  if (p === "auto") {
    hint = "Uses Claude Code if it is installed, otherwise a local Ollama model.";
  } else if (p === "claude") {
    $("aiModel").placeholder = "default — or sonnet, opus, haiku";
    hint = disc.claude
      ? "Claude Code is installed. Leave the model blank for its default."
      : "⚠ Claude Code (the claude command) was not found on this machine.";
  } else if (p === "ollama") {
    $("aiModel").placeholder = "e.g. qwen2.5-coder:1.5b";
    for (const m of disc.ollamaModels || []) dl.append(h("option", { value: m }));
    if (disc.ollamaError) hint = "⚠ " + disc.ollamaError;
    else if ((disc.ollamaModels || []).length) hint = "Installed: " + disc.ollamaModels.join(", ");
    else hint = "No models yet. Pull one first, e.g. ollama pull qwen2.5-coder:1.5b";
  } else if (p === "openai") {
    $("aiModel").placeholder = "e.g. qwen-plus";
    hint = "Any OpenAI-compatible endpoint (Qwen cloud, LM Studio, vLLM, llama.cpp). The key stays on this machine.";
  }
  $("aiHint").textContent = hint;
}

async function saveAiDialog() {
  const body = {
    provider: $("aiProvider").value,
    model: $("aiModel").value.trim(),
    url: $("aiURL").value.trim(),
    key: $("aiKey").value,
  };
  $("aiOk").disabled = true;
  try {
    const res = await api("PUT", "/api/ai", body);
    const st = res.status || {};
    app.info = app.info || {};
    app.info.assistant = st.available;
    app.info.assistantName = st.name;
    app.info.assistantError = st.error;
    applyAiName();
    renderAsk();
    $("aiDialog").close();
    if (st.available) toast("AI model set to " + (st.name || st.provider) + ".");
    else toast(st.error || "That model is not available.", true);
  } catch (err) {
    toast("Could not change the AI model: " + err.message, true);
  } finally {
    $("aiOk").disabled = false;
  }
}

$("asCfg").addEventListener("click", openAiDialog);
$("aiProvider").addEventListener("change", renderAiForm);
$("aiCancel").addEventListener("click", () => $("aiDialog").close());
$("aiOk").addEventListener("click", saveAiDialog);
