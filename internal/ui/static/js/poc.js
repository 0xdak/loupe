"use strict";
// PoC builder: collect flows one after another into an ordered proof-of-concept,
// then export a self-contained HTML report, an auto-captured PNG screenshot and a
// curl reproduction script. Everything is built client-side from traffic already
// loaded, so nothing about this machine is ever included — only the target
// request/response and what the tester types.

const SEVERITIES = ["Info", "Low", "Medium", "High", "Critical"];
const POC_RESP_CAP = 256 * 1024; // keep localStorage small; note when truncated

const poc = {
  steps: store.get("poc.steps", []), // [{n, id, target, method, url, status, ms, req, resp, respDec, truncated, proof}]
  title: store.get("poc.title", ""),
  severity: store.get("poc.severity", "High"),
  desc: store.get("poc.desc", ""),
};
poc.seq = poc.steps.reduce((m, s) => Math.max(m, s.n), 0) + 1;

function pocSave() {
  store.set("poc.steps", poc.steps);
  store.set("poc.title", poc.title);
  store.set("poc.severity", poc.severity);
  store.set("poc.desc", poc.desc);
  updatePocButton();
}

function updatePocButton() {
  const b = $("pocOpen"), c = $("pocCount");
  if (!b) return;
  if (c) c.textContent = poc.steps.length || "";
  b.title = poc.steps.length
    ? `Build a proof-of-concept from ${poc.steps.length} collected request${poc.steps.length > 1 ? "s" : ""}`
    : "Collect requests (right-click → Add to PoC), then build a proof-of-concept";
}

function capB64(b64) {
  // Cap a base64 payload to roughly POC_RESP_CAP decoded bytes.
  if (!b64) return { b64: "", truncated: false };
  const bytes = Math.floor(b64.length * 3 / 4);
  if (bytes <= POC_RESP_CAP) return { b64, truncated: false };
  const keep = Math.floor(POC_RESP_CAP / 3) * 4;
  return { b64: b64.slice(0, keep), truncated: true };
}

// addToPoc appends a flow detail (as returned by loadFlow) as the next step.
function addToPoc(d, label) {
  if (!d) return;
  const resp = capB64(d.response);
  const respDec = capB64(d.responseDecoded);
  let status = d.status || 0;
  if (!status && (resp.b64 || respDec.b64)) {
    const m = messageText(resp.b64, respDec.b64).match(/^HTTP\/[\d.]+\s+(\d{3})/);
    if (m) status = Number(m[1]);
  }
  const step = {
    n: poc.seq++, id: d.id ?? null,
    target: label || (d.host ? targetURL(d) : d.target || ""), method: d.method || "", url: d.url || "",
    status, ms: d.ms || 0,
    req: d.request || "", resp: resp.b64, respDec: respDec.b64,
    truncated: resp.truncated || respDec.truncated, proof: false,
  };
  if (!poc.steps.some((s) => s.proof)) step.proof = true; // first added is the proof by default
  poc.steps.push(step);
  pocSave();
  if (poc.steps.length === 1) step.proof = true;
  flash("proxy");
  toast(`Added to PoC (${poc.steps.length} step${poc.steps.length > 1 ? "s" : ""}). Click ⊕ PoC to build.`);
}

// ── Builder UI ──
function openPoc() {
  if (!poc.steps.length) { toast("No requests collected yet. Right-click a request → Add to PoC."); return; }
  $("pocWin").hidden = false;
  renderPocBuilder();
}
function closePoc() { $("pocWin").hidden = true; }

function proofStep() { return poc.steps.find((s) => s.proof) || poc.steps[0]; }

function renderPocBuilder() {
  $("pocTitle").value = poc.title;
  $("pocSeverity").value = poc.severity;
  $("pocDesc").value = poc.desc;
  const list = $("pocSteps");
  list.textContent = "";
  poc.steps.forEach((s, i) => {
    const proof = h("input", { type: "radio", name: "pocProof", title: "Use this response as the visual proof",
      onchange: () => { poc.steps.forEach((o) => (o.proof = false)); s.proof = true; pocSave(); renderPocPreview(); } });
    proof.checked = !!s.proof;
    list.append(h("div", { class: "poc-step" },
      h("span", { class: "poc-ord" }, String(i + 1)),
      h("div", { class: "poc-meta" },
        h("div", { class: "poc-line1" }, h("b", {}, s.method + " "), s.url),
        h("div", { class: "poc-line2 muted" },
          s.status ? "Status " + s.status : "no response",
          s.ms ? " · " + s.ms + " ms" : "", s.truncated ? " · body truncated" : "")),
      h("label", { class: "check poc-proof" }, proof, "proof"),
      h("button", { class: "btn", title: "Move up", disabled: i === 0, onclick: () => movePoc(i, -1) }, "↑"),
      h("button", { class: "btn", title: "Move down", disabled: i === poc.steps.length - 1, onclick: () => movePoc(i, 1) }, "↓"),
      h("button", { class: "btn", title: "Remove this step", onclick: () => removePoc(i) }, "×")));
  });
  renderPocPreview();
}
function movePoc(i, dir) {
  const j = i + dir;
  if (j < 0 || j >= poc.steps.length) return;
  [poc.steps[i], poc.steps[j]] = [poc.steps[j], poc.steps[i]];
  pocSave(); renderPocBuilder();
}
function removePoc(i) {
  const wasProof = poc.steps[i].proof;
  poc.steps.splice(i, 1);
  if (wasProof && poc.steps.length) poc.steps[poc.steps.length - 1].proof = true;
  pocSave();
  if (!poc.steps.length) { closePoc(); return; }
  renderPocBuilder();
}

// buildCard builds the finding card used for the on-screen preview and the PNG.
// It uses only inline styles and no external resources, so it rasterizes cleanly.
function buildCard() {
  const s = proofStep();
  const sevIdx = SEVERITIES.indexOf(poc.severity);
  const sevBg = ["#5C5550", "#7A6B2E", "#9B6A1E", "#9B2D43", "#6E1423"][sevIdx] || "#9B2D43";
  const mono = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
  const sans = "system-ui, -apple-system, Segoe UI, Roboto, sans-serif";
  const box = (style, ...kids) => h("div", { style }, ...kids);
  // A labeled message block showing the full text. Very large bodies are capped
  // so the rasterized canvas stays within the browser's limits; the complete
  // text is always in the downloadable HTML report.
  const msgBlock = (label, text, cap) => {
    let t = text || "(empty)";
    let note = "";
    if (t.length > cap) { t = t.slice(0, cap); note = "\n\n… truncated in this image — the full text is in the downloaded PoC report."; }
    return box("margin-top:12px;",
      box("font-size:11px;color:#8A817C;letter-spacing:.06em;text-transform:uppercase;margin-bottom:5px;", label),
      box(`font-family:${mono};font-size:11px;line-height:1.45;color:#C9C3BF;background:#1B1515;border:1px solid #3A3031;border-radius:3px;padding:10px 12px;white-space:pre-wrap;word-break:break-all;`, t),
      note ? box(`font-family:${mono};font-size:11px;color:#B5384F;margin-top:4px;`, note.trim()) : null);
  };
  const card = box(
    `width:760px;box-sizing:border-box;padding:22px 24px;background:#141011;color:#FAFAF8;font-family:${sans};`,
    box("display:flex;align-items:center;gap:10px;margin-bottom:14px;",
      box(`display:inline-block;padding:3px 10px;border-radius:3px;background:${sevBg};color:#fff;font-weight:700;font-size:12px;letter-spacing:.04em;`, poc.severity.toUpperCase()),
      box("font-size:12px;color:#8A817C;font-family:" + mono + ";", "loupe · proof of concept")),
    h("div", { style: "font-size:20px;font-weight:700;line-height:1.25;margin-bottom:6px;color:#fff;" }, poc.title || "Untitled finding"),
    box("font-size:12.5px;color:#E0556B;font-family:" + mono + ";margin-bottom:14px;word-break:break-all;", s.method + " " + s.url),
    poc.desc ? h("div", { style: "font-size:13px;line-height:1.5;color:#D8D2CE;margin-bottom:14px;white-space:pre-wrap;" }, poc.desc) : null,
    box("border-top:1px solid #3A3031;padding-top:12px;",
      box("font-size:11px;color:#8A817C;letter-spacing:.06em;text-transform:uppercase;",
        `${poc.steps.length} step${poc.steps.length > 1 ? "s" : ""} · proof: ${s.method}${s.status ? "  ·  HTTP " + s.status : ""}${s.ms ? "  ·  " + s.ms + " ms" : ""}`),
      msgBlock("Request", messageText(s.req), 16000),
      msgBlock("Response", messageText(s.resp, s.respDec), 48000)),
    box("margin-top:14px;font-size:11px;color:#6E655F;font-family:" + mono + ";", "Generated with Loupe — github.com/0xdak/loupe"));
  return card;
}

// nodeToPng rasterizes an in-DOM, inline-styled node to a PNG data URL via an
// SVG foreignObject. The node must use only inline styles and no cross-origin
// images, which keeps the canvas untainted and the export reliable.
async function nodeToPng(node, scale = 2) {
  const rect = node.getBoundingClientRect();
  const w = Math.ceil(rect.width) || 720, hh = Math.ceil(rect.height) || 200;
  const xml = new XMLSerializer().serializeToString(node);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${hh}">` +
    `<foreignObject x="0" y="0" width="100%" height="100%">${xml}</foreignObject></svg>`;
  const img = new Image();
  await new Promise((res, rej) => {
    img.onload = res; img.onerror = () => rej(new Error("render failed"));
    img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
  });
  const canvas = document.createElement("canvas");
  canvas.width = w * scale; canvas.height = hh * scale;
  const ctx = canvas.getContext("2d");
  ctx.scale(scale, scale);
  ctx.fillStyle = "#141011"; ctx.fillRect(0, 0, w, hh);
  ctx.drawImage(img, 0, 0);
  return canvas.toDataURL("image/png");
}

let pocPng = ""; // last captured screenshot data URL
let pocRenderSeq = 0; // discards stale async renders so previews never duplicate
async function renderPocPreview() {
  const my = ++pocRenderSeq;
  const host = $("pocCardHost"), shot = $("pocShot"), frameHost = $("pocFrame");
  host.textContent = ""; shot.textContent = ""; frameHost.textContent = "";
  const card = buildCard();
  host.append(card);
  // Capture the PNG automatically from the rendered card.
  try {
    const png = await nodeToPng(card, Math.min(2, window.devicePixelRatio || 1) * 2);
    if (my !== pocRenderSeq) return; // a newer render started; drop this one
    pocPng = png;
    shot.append(h("img", { src: pocPng, alt: "PoC screenshot", style: "display:block;width:100%;border:1px solid var(--line);border-radius:4px;" }));
  } catch {
    if (my !== pocRenderSeq) return;
    pocPng = "";
    shot.append(h("div", { class: "muted small" }, "Screenshot could not be captured in this browser; the HTML report still includes the rendered response."));
  }
  // Live render of the proof response, if it looks like HTML.
  const s = proofStep();
  const full = messageText(s.resp, s.respDec);
  const ct = headerOf(full, "content-type").toLowerCase();
  const [, body] = splitMessage(full);
  const looksHtml = ct.includes("html") || /<(!doctype|html|body|div|table|h1|p)\b/i.test(body.slice(0, 500));
  const pane = $("pocFramePane");
  if (looksHtml && body.trim()) {
    const iframe = h("iframe", { class: "poc-iframe", sandbox: "", title: "Rendered proof response" });
    iframe.srcdoc = renderBody(body, s.url);
    frameHost.append(iframe);
    if (pane) pane.hidden = false;
  } else if (pane) pane.hidden = true;
}

// renderBody prepares a response body for a sandboxed iframe: a <base> so the
// target's own relative CSS/images resolve, with scripts left to the sandbox.
function renderBody(body, url) {
  let base = "";
  try { base = new URL(url).origin + new URL(url).pathname.replace(/[^/]*$/, ""); } catch {}
  const tag = base ? `<base href="${esc(base)}">` : "";
  if (/<head\b/i.test(body)) return body.replace(/<head([^>]*)>/i, `<head$1>${tag}`);
  return tag + body;
}

// ── Escaping and curl ──
function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }

function stepCurl(s) {
  const target = (() => { try { return new URL(s.url).origin; } catch { return s.target; } })();
  return toCurl(messageText(s.req), target);
}

// ── Report ──
function buildReportHtml() {
  const now = new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC";
  const sevIdx = SEVERITIES.indexOf(poc.severity);
  const sevBg = ["#5C5550", "#7A6B2E", "#9B6A1E", "#9B2D43", "#6E1423"][sevIdx] || "#9B2D43";
  const steps = poc.steps.map((s, i) => {
    const reqText = messageText(s.req);
    const respText = messageText(s.resp, s.respDec) || "(no response captured)";
    const isProof = s.proof;
    let rendered = "";
    if (isProof) {
      const full = respText;
      const ct = headerOf(full, "content-type").toLowerCase();
      const [, body] = splitMessage(full);
      const looksHtml = ct.includes("html") || /<(!doctype|html|body|div|table|h1|p)\b/i.test(body.slice(0, 500));
      if (looksHtml && body.trim())
        rendered = `<p class="lbl">Rendered response (sandboxed, scripts disabled)</p>
          <iframe class="render" sandbox="" srcdoc="${esc(renderBody(body, s.url))}"></iframe>`;
    }
    return `<section class="step${isProof ? " proof" : ""}">
      <h3><span class="ord">${i + 1}</span> ${esc(s.method)} ${esc(s.url)} ${isProof ? '<span class="tag">PROOF</span>' : ""}</h3>
      <div class="meta">${s.status ? "HTTP " + s.status : "no response"}${s.ms ? " &middot; " + s.ms + " ms" : ""}${s.truncated ? " &middot; body truncated" : ""}</div>
      <p class="lbl">Request</p><pre class="req">${esc(reqText)}</pre>
      <p class="lbl">Response</p><pre class="resp">${esc(respText)}</pre>
      <p class="lbl">Reproduce</p><pre class="curl">${esc(stepCurl(s))}</pre>
      ${rendered}
    </section>`;
  }).join("\n");

  const shotImg = pocPng ? `<img class="shot" src="${pocPng}" alt="Proof screenshot">` : "";

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(poc.title || "Loupe PoC")}</title>
<style>
  :root{--bg:#141011;--panel:#1B1515;--line:#3A3031;--text:#FAFAF8;--muted:#8A817C;--accent:#E0556B;--accent2:#B5384F;
    --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.5;}
  .wrap{max-width:900px;margin:0 auto;padding:32px 22px 60px;}
  header{border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:22px;}
  .badge{display:inline-block;padding:3px 10px;border-radius:3px;background:${sevBg};color:#fff;font-weight:700;font-size:12px;letter-spacing:.04em;}
  h1{font-size:24px;margin:12px 0 6px;}
  .sub{font-family:var(--mono);font-size:12.5px;color:var(--accent);word-break:break-all;}
  .when{color:var(--muted);font-size:12px;margin-top:6px;}
  .desc{white-space:pre-wrap;margin:16px 0 0;color:#D8D2CE;}
  .shot{display:block;max-width:100%;margin:22px 0;border:1px solid var(--line);border-radius:4px;}
  h2{font-size:14px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:30px 0 10px;}
  .step{border:1px solid var(--line);border-radius:4px;padding:14px 16px;margin:0 0 16px;background:var(--panel);}
  .step.proof{border-color:var(--accent2);}
  .step h3{font-family:var(--mono);font-size:13px;font-weight:600;margin:0 0 4px;word-break:break-all;color:#fff;}
  .ord{display:inline-block;min-width:20px;height:20px;line-height:20px;text-align:center;background:var(--accent2);color:#fff;border-radius:3px;font-size:12px;margin-right:6px;}
  .tag{background:var(--accent2);color:#fff;font-size:10px;padding:1px 6px;border-radius:3px;letter-spacing:.06em;margin-left:6px;}
  .meta{color:var(--muted);font-size:12px;font-family:var(--mono);margin-bottom:10px;}
  .lbl{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:12px 0 4px;}
  pre{margin:0;background:var(--bg);border:1px solid var(--line);border-radius:3px;padding:10px 12px;overflow:auto;
    font-family:var(--mono);font-size:12px;line-height:1.45;white-space:pre-wrap;word-break:break-word;max-height:360px;}
  .render{width:100%;height:420px;border:1px solid var(--line);border-radius:3px;margin-top:4px;background:#fff;}
  footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:12px;font-family:var(--mono);}
  footer a{color:var(--accent);}
  @media print{body{background:#fff;color:#000}.step,pre{background:#fff}}
</style></head>
<body><div class="wrap">
  <header>
    <span class="badge">${esc(poc.severity)}</span>
    <h1>${esc(poc.title || "Untitled finding")}</h1>
    <div class="sub">${esc(proofStep().method + " " + proofStep().url)}</div>
    <div class="when">${now}</div>
    ${poc.desc ? `<div class="desc">${esc(poc.desc)}</div>` : ""}
  </header>
  ${shotImg}
  <h2>Steps to reproduce</h2>
  ${steps}
  <footer>Generated with <a href="https://github.com/0xdak/loupe">Loupe</a> — a single-binary intercepting proxy.</footer>
</div></body></html>`;
}

function slug() {
  return (poc.title || "loupe-poc").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "loupe-poc";
}
function download(name, blob) {
  const url = URL.createObjectURL(blob);
  const a = h("a", { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
function savePocHtml() {
  download(slug() + ".html", new Blob([buildReportHtml()], { type: "text/html" }));
  toast("PoC report saved.");
}
function savePocPng() {
  if (!pocPng) { toast("No screenshot was captured in this browser.", true); return; }
  const bytes = b64ToBytes(pocPng.split(",")[1]);
  download(slug() + ".png", new Blob([bytes], { type: "image/png" }));
  toast("Screenshot saved.");
}
function copyPocCurl() {
  const script = "#!/usr/bin/env bash\n# " + (poc.title || "Loupe PoC") + "\nset -e\n\n" +
    poc.steps.map((s, i) => `# Step ${i + 1}: ${s.method} ${s.url}\n${stepCurl(s)}`).join("\n\n") + "\n";
  copyText(script, "curl script");
}

// ── Wiring ──
function initPoc() {
  updatePocButton();
  $("pocOpen")?.addEventListener("click", openPoc);
  $("pocClose")?.addEventListener("click", closePoc);
  $("pocSaveHtml")?.addEventListener("click", savePocHtml);
  $("pocSavePng")?.addEventListener("click", savePocPng);
  $("pocCopyCurl")?.addEventListener("click", copyPocCurl);
  $("pocClear")?.addEventListener("click", () => {
    poc.steps = []; poc.seq = 1; pocSave(); closePoc(); toast("PoC cleared.");
  });
  $("pocTitle")?.addEventListener("input", (e) => { poc.title = e.target.value; pocSave(); });
  $("pocSeverity")?.addEventListener("change", (e) => { poc.severity = e.target.value; pocSave(); renderPocPreview(); });
  let descTimer = 0;
  $("pocDesc")?.addEventListener("input", (e) => {
    poc.desc = e.target.value; pocSave();
    clearTimeout(descTimer); descTimer = setTimeout(renderPocPreview, 250);
  });
  addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("pocWin").hidden) closePoc(); });
}
initPoc();
