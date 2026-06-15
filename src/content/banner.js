/**
 * On-page control banner (content script).
 *
 * A small, draggable, dismissible floating widget injected on in-scope pages.
 * It shows the active browsing identity, the replay target, a live findings
 * counter, and quick actions: capture this session, and "Switch user (safe)".
 *
 * Classic content script - no ES module imports - so storage keys and a tiny
 * bit of scope-matching are duplicated from the lib modules.
 */
(function () {
  const IDS_KEY = "azr.identities";
  const CONFIG_KEY = "azr.config";
  const RECORDS_KEY = "azr.records";
  const origin = location.origin;

  let host = null;
  let shadow = null;
  let root = null;
  let dismissed = false;
  let pos = null; // {top,left} once dragged

  function ensureHost() {
    if (host) return;
    host = document.createElement("div");
    host.id = "azr-banner-host";
    host.style.cssText = "all:initial;position:fixed;top:10px;right:10px;z-index:2147483647;";
    shadow = host.attachShadow({ mode: "open" });
    root = document.createElement("div");
    shadow.appendChild(root);
    (document.documentElement || document.body).appendChild(host);
  }

  function safeColor(c) {
    return /^#[0-9a-fA-F]{3,8}$/.test(c || "") ? c : "#bdf24e";
  }

  function inScope(config) {
    const inc = (config && config.includeScopes) || [];
    const exc = (config && config.excludeScopes) || [];
    const m = (pats) => pats.some((p) => globTest(p, location.href));
    return inc.length > 0 && m(inc) && !m(exc);
  }
  function globTest(glob, url) {
    try {
      const re = new RegExp(
        "^" +
          String(glob).trim().replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") +
          "$",
        "i"
      );
      return re.test(url);
    } catch {
      return false;
    }
  }

  function send(type) {
    try {
      chrome.runtime.sendMessage({ type, url: location.href }, () => void chrome.runtime.lastError);
    } catch {
      /* ignore */
    }
  }

  function btn(text, title, onClick, color) {
    const b = document.createElement("button");
    b.textContent = text;
    b.title = title;
    b.style.cssText =
      "all:unset;box-sizing:border-box;cursor:pointer;font:600 11px system-ui,sans-serif;color:#fff;" +
      "text-align:center;white-space:nowrap;" +
      "border:1px solid " + (color || "#3a3a3a") + ";border-radius:6px;padding:4px 8px;background:rgba(255,255,255,.06);";
    b.addEventListener("mouseenter", () => (b.style.background = "rgba(255,255,255,.16)"));
    b.addEventListener("mouseleave", () => (b.style.background = "rgba(255,255,255,.06)"));
    b.addEventListener("click", onClick);
    return b;
  }

  function clear() {
    if (root) root.innerHTML = "";
  }

  function render(identities, config, records) {
    if (dismissed) return clear();
    if (!inScope(config)) return clear();

    const browsing = identities.find((i) => i.id === config.browsingIdentityId) || null;
    const replay = identities.find((i) => i.id === config.replayIdentityId) || null;

    let bypassed = 0;
    let unclear = 0;
    for (const r of records || []) {
      if (r.verdict === "BYPASSED") bypassed++;
      else if (r.verdict === "UNCLEAR") unclear++;
    }

    ensureHost();
    root.innerHTML = "";

    const color = safeColor(browsing && browsing.color);
    const card = document.createElement("div");
    card.style.cssText =
      "display:flex;flex-direction:column;gap:7px;font:600 12px ui-monospace,SFMono-Regular,Menlo,monospace;" +
      "color:#e8ece4;background:rgba(10,12,10,.96);border:1px solid " + color + ";border-radius:10px;" +
      "padding:8px 10px;box-shadow:0 8px 26px -8px rgba(0,0,0,.6),0 0 16px -8px " + color + ";width:248px;box-sizing:border-box;";

    // ---- top row: drag grip, identity dot + text, close ----
    const row1 = document.createElement("div");
    row1.style.cssText = "display:flex;align-items:center;gap:8px;";

    const grip = document.createElement("span");
    grip.textContent = "⋮⋮";
    grip.title = "Drag to move";
    grip.style.cssText = "cursor:grab;color:#6e6e6e;letter-spacing:-2px;flex:none;";
    enableDrag(grip);

    const dot = document.createElement("span");
    dot.style.cssText = "width:9px;height:9px;border-radius:50%;flex:none;display:inline-block;background:" + color + ";";

    const text = document.createElement("div");
    text.style.cssText = "display:flex;flex-direction:column;gap:1px;line-height:1.25;flex:1;min-width:0;";
    const l1 = document.createElement("span");
    l1.style.cssText = "white-space:nowrap;overflow:hidden;text-overflow:ellipsis;";
    l1.textContent = browsing ? "Browsing as " + (browsing.label || "session") : "No browsing identity";
    const l2 = document.createElement("span");
    l2.style.cssText = "font-size:10px;color:#9aa498;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;";
    l2.textContent = replay ? "Replay → " + (replay.label || "B") : "Replay → (none)";
    text.appendChild(l1);
    text.appendChild(l2);

    const close = document.createElement("span");
    close.textContent = "×";
    close.title = "Hide on this page";
    close.style.cssText = "cursor:pointer;color:#9b9b9b;font-weight:700;padding:0 2px;flex:none;";
    close.addEventListener("click", () => {
      dismissed = true;
      clear();
    });

    row1.appendChild(grip);
    row1.appendChild(dot);
    row1.appendChild(text);
    if (bypassed || unclear) {
      const counter = document.createElement("span");
      counter.style.cssText =
        "flex:none;font-size:10px;padding:1px 6px;border-radius:5px;border:1px solid " +
        (bypassed ? "#ff5874;color:#ff5874;" : "#ffb454;color:#ffb454;");
      counter.textContent = bypassed ? bypassed + " ✗" : unclear + " ?";
      counter.title = `${bypassed} BYPASSED · ${unclear} UNCLEAR`;
      row1.appendChild(counter);
    }
    row1.appendChild(close);

    // ---- bottom row: full-width action buttons ----
    const row2 = document.createElement("div");
    row2.style.cssText = "display:flex;gap:6px;";
    const cap = btn("Capture", "Capture the session you're logged in as now", () => send("AZR_CAPTURE_IDENTITY"), "#bdf24e");
    const sw = btn(
      "Switch (safe)",
      "Clear local cookies + storage (no /logout) so you can log in as the next user",
      () => send("AZR_SWITCH_USER"),
      "#ffb454"
    );
    cap.style.flex = "1";
    sw.style.flex = "1";
    row2.appendChild(cap);
    row2.appendChild(sw);

    card.appendChild(row1);
    card.appendChild(row2);
    root.appendChild(card);

    if (pos) {
      host.style.top = pos.top + "px";
      host.style.left = pos.left + "px";
      host.style.right = "auto";
    }
  }

  function enableDrag(handle) {
    let sx, sy, st, sl;
    handle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      const rect = host.getBoundingClientRect();
      sx = e.clientX;
      sy = e.clientY;
      st = rect.top;
      sl = rect.left;
      handle.style.cursor = "grabbing";
      const move = (ev) => {
        pos = { top: Math.max(0, st + ev.clientY - sy), left: Math.max(0, sl + ev.clientX - sx) };
        host.style.top = pos.top + "px";
        host.style.left = pos.left + "px";
        host.style.right = "auto";
      };
      const up = () => {
        handle.style.cursor = "grab";
        document.removeEventListener("mousemove", move);
        document.removeEventListener("mouseup", up);
      };
      document.addEventListener("mousemove", move);
      document.addEventListener("mouseup", up);
    });
  }

  function load() {
    try {
      chrome.storage.local.get([IDS_KEY, CONFIG_KEY], (local) => {
        if (chrome.runtime.lastError) return;
        chrome.storage.session.get(RECORDS_KEY, (session) => {
          const records = (session && session[RECORDS_KEY]) || [];
          render(local[IDS_KEY] || [], local[CONFIG_KEY] || {}, records);
        });
      });
    } catch {
      /* extension context invalidated (e.g. reload) - ignore */
    }
  }

  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && (changes[IDS_KEY] || changes[CONFIG_KEY])) load();
      if (area === "session" && changes[RECORDS_KEY]) load();
    });
  } catch {
    /* ignore */
  }

  load();
})();
