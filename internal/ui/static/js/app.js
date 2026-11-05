"use strict";
// Tab navigation and start-up.

// flash highlights a main tab briefly, as Burp does when something is sent to it.
function flash(tab) {
  const b = $$("#mainTabs button").find((x) => x.dataset.tab === tab);
  if (!b || app.tab === tab) return;
  b.classList.add("alert");
  setTimeout(() => b.classList.remove("alert"), 2500);
}

for (const b of $$("#mainTabs button")) b.addEventListener("click", () => showTab(b.dataset.tab));
for (const section of $$("main > .tab")) {
  const tab = section.id.slice(4);
  for (const b of $$(".subtabs button", section)) b.addEventListener("click", () => { showSub(tab, b.dataset.sub); store.set("sub." + tab, b.dataset.sub); });
  const first = $$(".subtabs button.active", section)[0];
  if (first) showSub(tab, store.get("sub." + tab, first.dataset.sub));
}
on("tabShown", (tab) => {
  store.set("tab", tab);
  if (tab === "repeater") renderRepeater();
  if (tab === "intruder") renderIntruder();
});

for (const b of $$(".browserBtn")) {
  b.addEventListener("click", async () => {
    b.disabled = true;
    try { await api("POST", "/api/browser"); toast("Browser started. Pages you visit there appear in Proxy → HTTP history."); }
    catch (err) { toast("Could not start a browser: " + err.message, true); }
    finally { b.disabled = false; }
  });
}

// Theme: auto follows the system; light and dark override it.
function applyTheme(t) {
  if (t === "auto") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
  $("themeBtn").textContent = "Theme: " + t[0].toUpperCase() + t.slice(1);
}
applyTheme(store.get("theme", "auto"));
$("themeBtn").addEventListener("click", () => {
  const next = { auto: "light", light: "dark", dark: "auto" }[store.get("theme", "auto")];
  store.set("theme", next); applyTheme(next);
});

(async function start() {
  connectEvents();
  try {
    const [info, scope] = await Promise.all([getJSON("/api/info"), getJSON("/api/scope")]);
    app.info = info;
    applyAiName();
    for (const el of [$("proxyAddr"), ...$$(".proxyAddr")]) el.textContent = info.proxy;
    for (const b of $$(".browserBtn")) b.hidden = !info.browser;
    $("caSection").hidden = !info.mitm;
    app.scope = scope.patterns || [];
    emit("scopeChanged");
    await initProxy();
  } catch (err) {
    toast("Could not load data from lightproxy: " + err.message, true);
  }
  showTab(store.get("tab", "proxy"));
})();
