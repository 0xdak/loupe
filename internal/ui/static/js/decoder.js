"use strict";
// Decoder: a chain of panels. Each panel holds bytes; an operation chosen on
// a panel fills the next one, and editing a panel recomputes the rest.

const dec = { panels: [{ bytes: new Uint8Array(), op: null, view: "text" }] };

const OPS = {
  decode: { url: "URL", html: "HTML", base64: "Base64", hex: "ASCII hex", gzip: "Gzip", jwt: "JWT" },
  encode: { url: "URL", urlall: "URL (all characters)", html: "HTML", base64: "Base64", hex: "ASCII hex", gzip: "Gzip" },
  hash: { md5: "MD5", "sha-1": "SHA-1", "sha-256": "SHA-256", "sha-384": "SHA-384", "sha-512": "SHA-512" },
};
const hexOf = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

async function runOp(op, bytes) {
  const [kind, name] = op.split(":");
  const text = () => bytesToText(bytes);
  if (kind === "decode") {
    switch (name) {
      case "url": {
        const out = [];
        for (let i = 0; i < bytes.length; i++) {
          const c = bytes[i];
          if (c === 0x25 && i + 2 < bytes.length && /^[0-9a-f]{2}$/i.test(String.fromCharCode(bytes[i + 1], bytes[i + 2]))) {
            out.push(parseInt(String.fromCharCode(bytes[i + 1], bytes[i + 2]), 16)); i += 2;
          } else out.push(c === 0x2b ? 0x20 : c);
        }
        return new Uint8Array(out);
      }
      case "html": { const t = document.createElement("textarea"); t.innerHTML = text(); return textToBytes(t.value); }
      case "base64": {
        let s = text().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
        while (s.length % 4) s += "=";
        return b64ToBytes(s);
      }
      case "hex": {
        const s = text().replace(/0x|\\x|[\s:,-]/gi, "");
        if (!/^([0-9a-f]{2})*$/i.test(s)) throw new Error("not hexadecimal");
        return new Uint8Array(s.match(/../g)?.map((x) => parseInt(x, 16)) || []);
      }
      case "gzip": return stream(bytes, new DecompressionStream("gzip"));
      case "jwt": {
        const parts = text().trim().split(".");
        if (parts.length < 2) throw new Error("not a JWT");
        const part = (p) => { const b = bytesToText(b64url(p)); try { return JSON.stringify(JSON.parse(b), null, 2); } catch { return b; } };
        return textToBytes("// header\n" + part(parts[0]) + "\n\n// payload\n" + part(parts[1]) + (parts[2] ? "\n\n// signature (base64url)\n" + parts[2] : ""));
      }
    }
  }
  if (kind === "encode") {
    switch (name) {
      case "url": case "urlall": {
        let s = "";
        for (const c of bytes) {
          const ch = String.fromCharCode(c);
          s += name === "url" && /[A-Za-z0-9\-_.~]/.test(ch) ? ch : "%" + c.toString(16).toUpperCase().padStart(2, "0");
        }
        return textToBytes(s);
      }
      case "html": return textToBytes([...text()].map((ch) => {
        const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;" };
        if (map[ch]) return map[ch];
        const cp = ch.codePointAt(0);
        return cp > 0x7e ? "&#x" + cp.toString(16) + ";" : ch;
      }).join(""));
      case "base64": return textToBytes(bytesToB64(bytes));
      case "hex": return textToBytes(hexOf(bytes));
      case "gzip": return stream(bytes, new CompressionStream("gzip"));
    }
  }
  if (kind === "hash") {
    if (name === "md5") return textToBytes(hexOf(md5(bytes)));
    return textToBytes(hexOf(new Uint8Array(await crypto.subtle.digest(name.toUpperCase(), bytes))));
  }
  throw new Error("unknown operation");
}
function b64url(p) { let s = p.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return b64ToBytes(s); }
async function stream(bytes, transform) {
  const out = new Response(new Blob([bytes]).stream().pipeThrough(transform));
  return new Uint8Array(await out.arrayBuffer());
}

// md5 implements RFC 1321, which Web Crypto does not offer.
function md5(bytes) {
  const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;
  const len = bytes.length, nblk = ((len + 8) >>> 6) + 1;
  const w = new Uint32Array(nblk * 16);
  for (let i = 0; i < len; i++) w[i >> 2] |= bytes[i] << ((i % 4) * 8);
  w[len >> 2] |= 0x80 << ((len % 4) * 8);
  w[nblk * 16 - 2] = (len * 8) >>> 0;
  w[nblk * 16 - 1] = Math.floor(len / 0x20000000);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let blk = 0; blk < w.length; blk += 16) {
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + w[blk + g]) >>> 0;
      const s = S[(i >> 4) * 4 + (i % 4)];
      A = D; D = C; C = B; B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16);
  [a0, b0, c0, d0].forEach((v, i) => { for (let j = 0; j < 4; j++) out[i * 4 + j] = (v >>> (8 * j)) & 255; });
  return out;
}

function panelText(p) {
  if (p.view === "hex") return [...p.bytes].map((x) => x.toString(16).padStart(2, "0")).join(" ");
  p.latin = !isUTF8(p.bytes);
  return p.latin ? latin1(p.bytes) : bytesToText(p.bytes);
}
function parsePanel(p, value) {
  if (p.view === "hex") {
    const s = value.replace(/[\s:]/g, "");
    if (!/^([0-9a-f]{2})*[0-9a-f]?$/i.test(s)) throw new Error("invalid hex");
    return new Uint8Array((s.length % 2 ? s.slice(0, -1) : s).match(/../g)?.map((x) => parseInt(x, 16)) || []);
  }
  if (p.latin && ![...value].some((c) => c.charCodeAt(0) > 255)) return Uint8Array.from(value, (c) => c.charCodeAt(0));
  return textToBytes(value);
}

async function recompute(from) {
  for (let i = from; i < dec.panels.length; i++) {
    const p = dec.panels[i];
    if (!p.op) { dec.panels.length = i + 1; break; }
    const next = dec.panels[i + 1] || { op: null, view: "text" };
    try { next.bytes = await runOp(p.op, p.bytes); next.err = ""; }
    catch (err) { next.bytes = new Uint8Array(); next.err = "Could not " + p.op.replace(":", " as ") + ": " + (err.message || err); next.op = null; }
    dec.panels[i + 1] = next;
  }
}

function renderDecoder(skip = -1) {
  const list = $("decList");
  dec.panels.forEach((p, i) => {
    let el = list.children[i];
    if (!el) { el = buildPanel(i); list.append(el); }
    if (i !== skip) el.querySelector("textarea").value = panelText(p);
    el.querySelector(".dec-err").textContent = p.err || "";
    el.querySelector(".dec-len").textContent = fmtNum(p.bytes.length) + " bytes";
    for (const r of el.querySelectorAll("input[type=radio]")) r.checked = r.value === p.view;
    for (const kind of ["decode", "encode", "hash"]) {
      const sel = el.querySelector(".op-" + kind);
      sel.value = p.op && p.op.startsWith(kind + ":") ? p.op : "";
    }
  });
  while (list.children.length > dec.panels.length) list.lastElementChild.remove();
}
function buildPanel(i) {
  const ta = h("textarea", { spellcheck: "false", placeholder: i === 0 ? "Paste or type data to decode or encode…" : "" });
  ta.addEventListener("input", async () => {
    const p = dec.panels[i];
    try { p.bytes = parsePanel(p, ta.value); p.err = ""; } catch (err) { p.err = err.message; renderDecoder(i); return; }
    await recompute(i);
    renderDecoder(i);
  });
  const selects = Object.entries(OPS).map(([kind, ops]) => {
    const sel = h("select", { class: "op-" + kind }, h("option", { value: "" }, kind === "hash" ? "Hash…" : kind[0].toUpperCase() + kind.slice(1) + " as…"),
      Object.entries(ops).map(([k, label]) => h("option", { value: kind + ":" + k }, label)));
    sel.addEventListener("change", async () => {
      dec.panels[i].op = sel.value || null;
      dec.panels.length = i + 1;
      await recompute(i);
      renderDecoder();
    });
    return sel;
  });
  const name = "decview" + i + "-" + Math.random().toString(36).slice(2);
  const radio = (v, label) => {
    const r = h("input", { type: "radio", name, value: v });
    r.addEventListener("change", () => { dec.panels[i].view = v; renderDecoder(); });
    return h("label", { class: "check" }, r, label);
  };
  return h("div", { class: "dec-panel" },
    h("div", {}, ta, h("div", { class: "dec-err" }), h("div", { class: "muted small dec-len" })),
    h("div", { class: "dec-side" }, h("div", { class: "modes" }, radio("text", "Text"), radio("hex", "Hex")), ...selects,
      h("button", { onclick: () => smartDecode(i) }, "Smart decode")));
}

// smartDecode applies decodings that the data looks like it needs, repeatedly.
async function smartDecode(i) {
  for (let step = 0; step < 10; step++) {
    const p = dec.panels[i];
    const s = bytesToText(p.bytes).trim();
    let op = null;
    if (p.bytes[0] === 0x1f && p.bytes[1] === 0x8b) op = "decode:gzip";
    else if (/^eyJ[\w-]+\.[\w-]+(\.[\w-]*)?$/.test(s)) op = "decode:jwt";
    else if (/%[0-9a-f]{2}/i.test(s)) op = "decode:url";
    else if (/&(#x?[0-9a-f]+|[a-z]+);/i.test(s)) op = "decode:html";
    else if (s.length >= 8 && s.length % 2 === 0 && /^[0-9a-f]+$/i.test(s)) op = "decode:hex";
    else if (s.length >= 4 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) {
      try { const out = await runOp("decode:base64", p.bytes); if (out.length && isUTF8(out) && !/[\x00-\x08\x0e-\x1f]/.test(bytesToText(out))) op = "decode:base64"; } catch {}
    }
    if (!op) break;
    p.op = op;
    dec.panels.length = i + 1;
    await recompute(i);
    if (dec.panels[i + 1].err) break;
    i++;
  }
  renderDecoder();
}

function sendToDecoder(text) {
  dec.panels = [{ bytes: textToBytes(text), op: null, view: "text" }];
  $("decList").textContent = "";
  renderDecoder();
  flash("decoder");
  toast("Sent to Decoder.");
}
$("decReset").addEventListener("click", () => { dec.panels = [{ bytes: new Uint8Array(), op: null, view: "text" }]; $("decList").textContent = ""; renderDecoder(); });
renderDecoder();
