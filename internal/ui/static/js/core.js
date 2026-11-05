"use strict";
// Shared helpers: DOM, API, message viewer, menus, tables, live events.

const $ = (id) => document.getElementById(id);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

// h builds an element: h("td", {class: "num", onclick: fn}, "text", child…)
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const store = {
  get(k, d) { try { const v = localStorage.getItem("lp." + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("lp." + k, JSON.stringify(v)); } catch {} },
};

function toast(msg, isErr) {
  const t = h("div", { class: "toast" + (isErr ? " err" : "") }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), isErr ? 7000 : 3000);
}

// api sends JSON; every change carries the header the server requires.
async function api(method, path, body, signal) {
  const res = await fetch(path, {
    method, signal,
    headers: { "X-Lightproxy": "1", "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error((await res.text()).trim() || res.statusText);
  return res.status === 204 ? null : res.json();
}
const getJSON = (path) => api("GET", path);

// ── Bytes and text ──
const utf8 = new TextDecoder("utf-8");
const utf8Strict = new TextDecoder("utf-8", { fatal: true });
function b64ToBytes(b64) {
  if (!b64) return new Uint8Array();
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
function bytesToB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
const bytesToText = (b) => utf8.decode(b);
const textToBytes = (t) => new TextEncoder().encode(t);
function isUTF8(b) { try { utf8Strict.decode(b); return true; } catch { return false; } }
function latin1(b) { let s = ""; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000)); return s; }

function fmtSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}
const fmtNum = (n) => n.toLocaleString("en-US");
const fmtTime = (t) => new Date(t).toLocaleTimeString("en-GB", { hour12: false });

function splitMessage(text) {
  let cut = text.indexOf("\r\n\r\n"), sep = 4;
  const lf = text.indexOf("\n\n");
  if (lf >= 0 && (cut < 0 || lf < cut)) { cut = lf; sep = 2; }
  if (cut < 0) return [text, ""];
  return [text.slice(0, cut + sep), text.slice(cut + sep)];
}
function headerOf(text, name) {
  const [head] = splitMessage(text);
  for (const line of head.split(/\r?\n/).slice(1)) {
    const i = line.indexOf(":");
    if (i > 0 && line.slice(0, i).trim().toLowerCase() === name.toLowerCase()) return line.slice(i + 1).trim();
  }
  return "";
}

// ── Message viewer: Pretty / Raw / Hex, like Burp's message editor ──
class Viewer {
  constructor(el, { title = "Request", editable = false, http = true, mode } = {}) {
    this.el = el; this.editable = editable; this.http = http;
    this.mode = mode || store.get("viewerMode." + (editable ? "edit" : "view"), editable ? "raw" : "pretty");
    this.text = ""; this.bytes = null; this.decoded = null; this.dirty = false; this.onInput = null;
    el.classList.add("viewer");
    el.textContent = "";
    this.tabs = {};
    const head = h("div", { class: "vhead" }, h("span", { class: "vtitle" }, title));
    for (const m of ["pretty", "raw", "hex"]) {
      this.tabs[m] = h("button", { class: "vtab", onclick: () => this.setMode(m) }, m[0].toUpperCase() + m.slice(1));
      head.append(this.tabs[m]);
    }
    this.info = h("span", { class: "vinfo" });
    head.append(this.info);
    this.body = h("div", { class: "vbody" });
    el.append(head, this.body);
    if (editable) {
      this.ta = h("textarea", { spellcheck: "false" });
      this.ta.addEventListener("input", () => { this.text = this.ta.value; this.dirty = true; this.bytes = null; this.onInput?.(); this.updateInfo(); });
    }
    this.placeholder = "";
    this.showEncoded = false; // show the compressed body instead of the decoded one
    this.render();
  }
  setMode(m) {
    if (this.editable && this.mode === "raw") this.text = this.ta.value;
    this.mode = m;
    store.set("viewerMode." + (this.editable ? "edit" : "view"), m);
    this.render();
  }
  // set shows bytes; decoded is the message with its body decompressed, for Pretty.
  set(bytes, decoded = null, placeholder = "") {
    this.bytes = bytes; this.decoded = decoded; this.placeholder = placeholder; this.showEncoded = false;
    this.text = bytes ? bytesToText(bytes) : "";
    this.dirty = false;
    this.render();
  }
  setText(text) { this.set(text === null ? null : textToBytes(text)); }
  getText() {
    if (this.editable && this.mode === "raw") return this.ta.value;
    const shown = this.shown();
    return shown ? bytesToText(shown) : this.text;
  }
  getBytes() { return this.bytes && !this.dirty ? this.bytes : textToBytes(this.getText()); }
  selection() {
    if (this.editable && this.mode === "raw") return this.ta.value.slice(this.ta.selectionStart, this.ta.selectionEnd);
    const s = window.getSelection();
    return s && this.body.contains(s.anchorNode) ? s.toString() : "";
  }
  updateInfo() {
    const n = this.bytes ? this.bytes.length : textToBytes(this.getText()).length;
    this.info.textContent = (this.bytes || this.text) ? fmtNum(n) + " bytes" : "";
    if (this.decoded) {
      this.info.append(" · ", h("button", {
        class: "vtab", title: "The body was sent compressed (Content-Encoding). Toggle between the decoded body and the bytes on the wire.",
        onclick: () => { this.showEncoded = !this.showEncoded; this.render(); },
      }, this.showEncoded ? "Show decoded" : "Show compressed"));
    }
  }
  // shown is the message as displayed: decoded unless the compressed bytes were asked for.
  shown() { return this.decoded && !this.showEncoded ? this.decoded : null; }
  render() {
    for (const [m, b] of Object.entries(this.tabs)) b.classList.toggle("active", m === this.mode);
    this.body.textContent = "";
    this.updateInfo();
    const empty = !this.text && !this.editable;
    if (empty) { this.body.append(h("div", { class: "placeholder" }, this.placeholder)); return; }
    if (this.mode === "raw" && this.editable) {
      this.ta.value = this.text;
      this.body.append(this.ta);
      return;
    }
    const shown = this.shown();
    if (this.mode === "hex") { this.body.append(hexDump(shown || this.getBytes())); return; }
    let text = shown ? bytesToText(shown) : this.text;
    if (this.mode === "pretty") text = prettyMessage(text, this.http);
    this.body.append(this.http ? renderHTTP(text) : h("pre", {}, text));
  }
  focus() { if (this.editable && this.mode === "raw") this.ta.focus(); }
}

function renderHTTP(text) {
  const pre = h("pre");
  const [head, body] = splitMessage(text);
  const lines = head.split(/(\r?\n)/);
  let first = true;
  for (const part of lines) {
    if (/^\r?\n$/.test(part)) { pre.append(part); continue; }
    if (!part) continue;
    if (first) { pre.append(h("span", { class: "fl" }, part)); first = false; continue; }
    const i = part.indexOf(":");
    if (i > 0) pre.append(h("span", { class: "hn" }, part.slice(0, i)), part.slice(i));
    else pre.append(part);
  }
  if (body) pre.append(body.length > 2_000_000 ? body.slice(0, 2_000_000) + "\n… (truncated for display)" : body);
  return pre;
}

function prettyMessage(text, http) {
  const [head, body] = http ? splitMessage(text) : ["", text];
  const t = body.trim();
  if ((t.startsWith("{") || t.startsWith("[")) && t.length < 5_000_000) {
    try { return head + JSON.stringify(JSON.parse(t), null, 2); } catch {}
  }
  if (http && /application\/x-www-form-urlencoded/i.test(headerOf(text, "Content-Type")) && t && !t.includes("\n")) {
    return head + t.split("&").join("&\n");
  }
  return head + body;
}

function hexDump(bytes) {
  const max = 256 * 1024;
  const n = Math.min(bytes.length, max);
  const lines = [];
  for (let off = 0; off < n; off += 16) {
    let hex = "", asc = "";
    for (let i = 0; i < 16; i++) {
      const b = bytes[off + i];
      if (off + i < n) { hex += b.toString(16).padStart(2, "0") + " "; asc += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."; }
      else hex += "   ";
      if (i === 7) hex += " ";
    }
    lines.push(off.toString(16).padStart(8, "0") + "  " + hex + " " + asc);
  }
  if (bytes.length > max) lines.push(`… showing the first ${fmtNum(max)} of ${fmtNum(bytes.length)} bytes`);
  return h("pre", { class: "hex" }, lines.join("\n"));
}

// pair creates a request and a response viewer side by side.
function makePair(el, opts = {}) {
  el.textContent = "";
  const left = h("div"), right = h("div"), split = h("div", { class: "vsplit" });
  el.append(left, split, right);
  vsplit(split, el);
  return {
    req: new Viewer(left, { title: "Request", ...opts.req }),
    resp: new Viewer(right, { title: "Response", ...opts.resp }),
  };
}

// ── Splitters ──
// hsplit resizes the bottom part of a grid whose last row uses var(--split).
function hsplit(handle, container) {
  drag(handle, (ev, rect) => container.style.setProperty("--split",
    Math.min(Math.max(rect.bottom - ev.clientY, 80), rect.height - 120) + "px"), container);
}
// vsplit resizes the first column of a three-column grid (left, handle, right).
function vsplit(handle, container) {
  drag(handle, (ev, rect) => {
    const x = Math.min(Math.max(ev.clientX - rect.left, 120), rect.width - 120);
    container.style.gridTemplateColumns = `minmax(0, ${x}px) 5px minmax(0, 1fr)`;
  }, container);
}
function drag(handle, onMove, container) {
  handle.addEventListener("pointerdown", (e) => {
    e.preventDefault();
    const rect = container.getBoundingClientRect();
    const move = (ev) => onMove(ev, rect);
    const up = () => { removeEventListener("pointermove", move); removeEventListener("pointerup", up); };
    addEventListener("pointermove", move); addEventListener("pointerup", up);
  });
}

// ── Context menu ──
function showMenu(e, items) {
  e.preventDefault();
  const menu = $("menu");
  menu.textContent = "";
  for (const it of items) {
    if (it === "-") { menu.append(h("hr")); continue; }
    menu.append(h("button", {
      disabled: it.disabled, onclick: () => { menu.hidden = true; it.action(); },
    }, it.label, it.key ? h("span", { class: "key" }, it.key) : null));
  }
  menu.hidden = false;
  const r = menu.getBoundingClientRect();
  menu.style.left = Math.min(e.clientX, innerWidth - r.width - 4) + "px";
  menu.style.top = Math.min(e.clientY, innerHeight - r.height - 4) + "px";
}
addEventListener("click", () => { $("menu").hidden = true; });
addEventListener("blur", () => { $("menu").hidden = true; });
addEventListener("keydown", (e) => { if (e.key === "Escape") $("menu").hidden = true; });

async function copyText(text, what) {
  try { await navigator.clipboard.writeText(text); toast(what + " copied to the clipboard."); }
  catch { toast("Could not access the clipboard.", true); }
}

// ── Sortable table ──
// SortTable keeps rows (objects) rendered in a tbody, sorted by a column key.
class SortTable {
  constructor(table, { render, key = "id", dir = "asc", values = {}, onSelect, onMenu, filter }) {
    this.table = table; this.tbody = table.tBodies[0]; this.render = render;
    this.key = key; this.dir = dir; this.values = values; this.onSelect = onSelect; this.filter = filter || (() => true);
    this.rows = new Map(); // id -> {item, tr}
    this.selected = null;
    for (const th of $$("th.sort", table)) {
      th.addEventListener("click", () => {
        const k = th.dataset.key;
        this.dir = this.key === k && this.dir === "asc" ? "desc" : "asc";
        this.key = k;
        this.resort();
      });
    }
    this.markHeader();
    this.tbody.addEventListener("click", (e) => { const tr = e.target.closest("tr"); if (tr) this.select(tr.dataset.id); });
    if (onMenu) this.tbody.addEventListener("contextmenu", (e) => {
      const tr = e.target.closest("tr"); if (!tr) return;
      this.select(tr.dataset.id); onMenu(e, this.rows.get(this.idOf(tr)).item);
    });
  }
  idOf(tr) { return isNaN(tr.dataset.id) ? tr.dataset.id : Number(tr.dataset.id); }
  markHeader() { for (const th of $$("th.sort", this.table)) th.dataset.dir = th.dataset.key === this.key ? this.dir : ""; }
  value(item) { const f = this.values[this.key]; return f ? f(item) : item[this.key]; }
  cmp(a, b) {
    let x = this.value(a), y = this.value(b);
    if (x === undefined || x === null) x = ""; if (y === undefined || y === null) y = "";
    let r = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true });
    if (r === 0) r = (a.id ?? a.n) - (b.id ?? b.n);
    return this.dir === "asc" ? r : -r;
  }
  add(item) {
    const id = item.id ?? item.n;
    const old = this.rows.get(id);
    const tr = this.render(item);
    tr.dataset.id = id;
    tr.hidden = !this.filter(item);
    if (old) { old.tr.replaceWith(tr); old.item = item; old.tr = tr; if (this.selected === id) tr.classList.add("sel"); return tr; }
    this.rows.set(id, { item, tr });
    let after = this.tbody.lastElementChild;
    while (after && this.cmp(this.rows.get(this.idOf(after)).item, item) > 0) after = after.previousElementSibling;
    this.tbody.insertBefore(tr, after ? after.nextSibling : this.tbody.firstChild);
    return tr;
  }
  resort() {
    this.markHeader();
    const list = [...this.rows.values()].sort((a, b) => this.cmp(a.item, b.item));
    for (const r of list) this.tbody.append(r.tr);
  }
  refilter() { for (const r of this.rows.values()) r.tr.hidden = !this.filter(r.item); }
  clear() { this.rows.clear(); this.tbody.textContent = ""; this.selected = null; }
  visibleCount() { let n = 0; for (const r of this.rows.values()) if (!r.tr.hidden) n++; return n; }
  select(id) {
    if (id === undefined || id === null) return;
    id = isNaN(id) ? id : Number(id);
    const r = this.rows.get(id);
    if (!r) return;
    this.tbody.querySelector("tr.sel")?.classList.remove("sel");
    r.tr.classList.add("sel");
    r.tr.scrollIntoView({ block: "nearest" });
    this.selected = id;
    this.onSelect?.(r.item);
  }
  step(dir) {
    let tr = this.selected !== null ? this.rows.get(this.selected)?.tr : null;
    if (!tr) { tr = [...this.tbody.children].find((r) => !r.hidden); if (tr) this.select(tr.dataset.id); return; }
    do { tr = dir > 0 ? tr.nextElementSibling : tr.previousElementSibling; } while (tr && tr.hidden);
    if (tr) this.select(tr.dataset.id);
  }
  current() { return this.selected === null ? null : this.rows.get(this.selected)?.item; }
}

// ── Live events ──
const bus = {};
function on(name, fn) { (bus[name] ||= []).push(fn); }
function emit(name, data) { for (const fn of bus[name] || []) fn(data); }
function connectEvents() {
  const es = new EventSource("/api/events");
  es.onopen = () => { $("live").textContent = "live"; $("live").classList.add("on"); emit("open"); };
  es.onerror = () => { $("live").textContent = "disconnected"; $("live").classList.remove("on"); };
  es.onmessage = (e) => emit("flow", JSON.parse(e.data));
  for (const name of ["intercept", "scope", "intruder", "ws"]) es.addEventListener(name, (e) => emit(name, JSON.parse(e.data)));
}

// ── Shared state and actions ──
const app = {
  info: {}, scope: [], flows: new Map(), tab: "proxy", sub: {},
};

function targetURL(f) { return (f.tls ? "https://" : "http://") + f.host; }
function hostOnly(h) {
  if (h.startsWith("[")) return h.slice(1, h.indexOf("]"));
  const i = h.lastIndexOf(":");
  return (i > 0 && h.indexOf(":") === i ? h.slice(0, i) : h).toLowerCase();
}
async function loadFlow(id) { return getJSON("/api/flows/" + id); }

async function setScope(patterns) {
  const s = await api("PUT", "/api/scope", { patterns });
  app.scope = s.patterns || [];
  emit("scopeChanged");
}

function toCurl(text, target) {
  const [head, body] = splitMessage(text.replace(/\r\n/g, "\n"));
  const lines = head.trim().split("\n");
  const [method, path] = lines[0].split(" ");
  const q = (s) => "'" + s.replace(/'/g, "'\\''") + "'";
  const parts = ["curl", "-i", "-s", "-k", "-X", method];
  for (const l of lines.slice(1)) {
    const name = l.split(":")[0].trim().toLowerCase();
    if (["host", "content-length", "connection"].includes(name)) continue;
    parts.push("-H", q(l));
  }
  if (body) parts.push("--data-binary", q(body));
  parts.push(q(target + path));
  return parts.join(" ");
}

// flowMenu is the right-click menu for an HTTP message.
function flowMenu(e, f, getDetail) {
  const host = hostOnly(f.host || "");
  const inScope = app.scope.includes(host);
  const http = f.method !== "CONNECT";
  showMenu(e, [
    { label: "✦ Ask Claude", key: "Ctrl+J", disabled: !http || !f.id, action: () => askAboutFlow(f.id) },
    "-",
    { label: "Send to Repeater", key: "Ctrl+R", disabled: !http, action: async () => { const d = await getDetail(); sendToRepeater(targetURL(d), bytesToText(b64ToBytes(d.request))); } },
    { label: "Send to Intruder", key: "Ctrl+I", disabled: !http, action: async () => { const d = await getDetail(); sendToIntruder(targetURL(d), bytesToText(b64ToBytes(d.request))); } },
    { label: "Send to Decoder", action: async () => { const d = await getDetail(); sendToDecoder(bytesToText(b64ToBytes(d.request))); } },
    "-",
    inScope ? { label: "Remove from scope", action: () => setScope(app.scope.filter((p) => p !== host)).then(() => toast(host + " removed from scope.")) }
      : { label: "Add to scope", disabled: !host, action: () => setScope([...app.scope, host]).then(() => toast(host + " added to scope.")).catch((err) => toast(err.message, true)) },
    "-",
    { label: "Copy URL", action: () => copyText(f.url, "URL") },
    { label: "Copy as curl command", disabled: !http, action: async () => { const d = await getDetail(); copyText(toCurl(bytesToText(b64ToBytes(d.request)), targetURL(d)), "curl command"); } },
  ]);
}

function showTab(tab, sub) {
  app.tab = tab;
  for (const b of $$("#mainTabs button")) b.classList.toggle("active", b.dataset.tab === tab);
  for (const s of $$("main > .tab")) s.hidden = s.id !== "tab-" + tab;
  if (sub) showSub(tab, sub);
  emit("tabShown", tab);
}
function showSub(tab, sub) {
  const section = $("tab-" + tab);
  app.sub[tab] = sub;
  for (const b of $$(".subtabs button", section)) b.classList.toggle("active", b.dataset.sub === sub);
  for (const s of $$(":scope > .sub", section)) s.hidden = s.id !== sub;
  emit("subShown", sub);
}
