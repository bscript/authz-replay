import { emptyIdentity, summarize, hasCredentials } from "../lib/identities.js";
import { prettyBody, DEFAULT_VOLATILE_PATTERNS } from "../lib/classify.js";
import { toCurl, toFetch } from "../lib/curl.js";

const $ = (sel) => document.querySelector(sel);
const ACK_KEY = "azr.ack";

let state = { identities: [], config: { includeScopes: [] }, records: [] };
const expanded = new Set();
const selected = new Set(); // record ids picked for sequence replay
let filter = { verdict: "all", search: "" };
let laneView = "stacked"; // "stacked" | "columns"
// Main content area is either the records list or an inline identity editor.
let view = { mode: "records" };

init();

async function init() {
  await maybeFirstRun();
  const lv = await chrome.storage.local.get("azr.laneView");
  laneView = lv["azr.laneView"] === "columns" ? "columns" : "stacked";
  wire();
  updateLaneToggle();
  await refresh();

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && changes["azr.records"]) {
      state.records = changes["azr.records"].newValue || [];
      if (view.mode === "records") {
        renderVerdictChips();
        renderRecords();
      }
    }
    if (area === "local") {
      if (changes["azr.config"]) state.config = changes["azr.config"].newValue || state.config;
      if (changes["azr.identities"]) state.identities = changes["azr.identities"].newValue || state.identities;
      if (changes["azr.config"] || changes["azr.identities"]) {
        renderIdentities();
        if (!$("#settings").classList.contains("hidden")) renderSettingsValues();
      }
    }
  });
}

async function maybeFirstRun() {
  const got = await chrome.storage.local.get(ACK_KEY);
  if (got[ACK_KEY]) return;
  $("#firstrun").classList.remove("hidden");
}

function send(type, extra = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, ...extra }, (resp) => {
      const err = chrome.runtime.lastError;
      if (err) return reject(new Error(err.message));
      if (!resp) return reject(new Error("No response from background worker"));
      if (!resp.ok) return reject(new Error(resp.error || "request failed"));
      resolve(resp.result);
    });
  });
}

async function refresh() {
  state = await send("AZR_GET_STATE");
  renderAll();
}

/* --------------------------------------------------------------- wiring -- */

function wire() {
  $("#ack").addEventListener("click", async () => {
    await chrome.storage.local.set({ [ACK_KEY]: Date.now() });
    $("#firstrun").classList.add("hidden");
  });
  $("#capture").addEventListener("click", captureSession);
  $("#switch").addEventListener("click", switchUser);
  $("#export").addEventListener("click", exportReport);
  $("#seq-run").addEventListener("click", replaySequence);
  $("#seq-clear").addEventListener("click", () => { selected.clear(); updateSeqBar(); renderRecords(); });
  $("#clear").addEventListener("click", async () => {
    if (!confirm("Clear all captured requests & findings?\n\nYour saved identities are kept.")) return;
    selected.clear();
    state = await send("AZR_CLEAR");
    renderAll();
  });
  $("#clear-identities").addEventListener("click", async () => {
    if (!state.identities.length) return;
    if (!confirm("Remove all captured identities?\n\nYour captured requests & findings are kept.")) return;
    state = await send("AZR_SAVE_IDENTITIES", { identities: [] });
    view = { mode: "records" };
    renderAll();
    toast("Cleared all identities.", "info");
  });
  $("#settings-btn").addEventListener("click", () => {
    $("#settings").classList.toggle("hidden");
    if (!$("#settings").classList.contains("hidden")) renderSettingsValues();
  });
  $("#settings-close").addEventListener("click", () => $("#settings").classList.add("hidden"));
  $("#save-settings").addEventListener("click", saveSettings);
  $("#reset-volatile").addEventListener("click", () => {
    $("#volatile").value = DEFAULT_VOLATILE_PATTERNS.join("\n");
  });
  $("#enabled").addEventListener("change", (e) => setConfig({ enabled: e.target.checked }));
  $("#auto-get").addEventListener("change", (e) => setConfig({ autoReplayGet: e.target.checked }));
  $("#skip-auth").addEventListener("change", (e) => setConfig({ skipAuthEndpoints: e.target.checked }));
  $("#search").addEventListener("input", (e) => { filter.search = e.target.value.toLowerCase(); renderRecords(); });
  document.querySelectorAll("#laneview .seg-btn").forEach((b) =>
    b.addEventListener("click", async () => {
      laneView = b.dataset.v;
      await chrome.storage.local.set({ "azr.laneView": laneView });
      updateLaneToggle();
      if (view.mode === "records") renderRecords();
    })
  );
}

function updateLaneToggle() {
  document.querySelectorAll("#laneview .seg-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.v === laneView)
  );
}

async function setConfig(patch) {
  state = await send("AZR_SET_CONFIG", { config: patch });
}

function linesOf(id) {
  return $(id).value.split("\n").map((s) => s.trim()).filter(Boolean);
}

async function saveSettings() {
  const patch = {
    includeScopes: linesOf("#include"),
    excludeScopes: linesOf("#exclude"),
    customAuthHeaderNames: linesOf("#auth-headers"),
    tokenStorageKeys: linesOf("#token-keys"),
    volatileFieldPatterns: linesOf("#volatile"),
    ownerMarkers: linesOf("#owner-markers"),
    csrfHeaderNames: linesOf("#csrf-headers"),
  };
  state = await send("AZR_SET_CONFIG", { config: patch });
  renderVerdictChips();
  if (view.mode === "records") renderRecords();
  toast("Settings saved - findings re-classified.", "success");
}

async function captureSession() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) return toast("Open a normal http(s) page in this tab first.", "warning");
    const result = await send("AZR_CAPTURE_IDENTITY", { url: tab.url, tabId: tab.id });
    state = result;
    view = { mode: "records" };
    renderAll();
    const c = result.captured;
    const bits = [];
    if (c.cookieCount) bits.push(`${c.cookieCount} cookie${c.cookieCount > 1 ? "s" : ""}`);
    if (c.authHeaders?.length) bits.push(c.authHeaders.join(" + "));
    if (c.tokenCount) bits.push(`${c.tokenCount} token${c.tokenCount > 1 ? "s" : ""}`);
    const creds = bits.join(" + ") || "session";
    if (c.refreshed) {
      toast(`Refreshed ${c.label} (${creds}) - same identity, no duplicate added.`, "info");
    } else {
      toast(`Captured ${c.label} (${creds}). Switch user and capture the next account.`, "success");
    }
  } catch (err) {
    toast(String(err.message || err), "danger");
  }
}

async function switchUser() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) return toast("Open the target page first.", "warning");
    const result = await send("AZR_SWITCH_USER", { url: tab.url, tabId: tab.id });
    state = result;
    renderAll();
    const what = (result.cleared || []).join(", ") || "local data";
    toast(`Cleared ${what} (no /logout). Reloading - log in as the next user.`, "info");
  } catch (err) {
    toast(String(err.message || err), "danger");
  }
}

/* ---------------------------------------------------------------- render - */

function renderAll() {
  renderIdentities();
  renderSettingsValues();
  renderVerdictChips();
  renderMain();
}

function renderMain() {
  if (view.mode === "editor") renderEditor();
  else renderRecords();
}

function renderSettingsValues() {
  const c = state.config;
  $("#enabled").checked = !!c.enabled;
  $("#auto-get").checked = !!c.autoReplayGet;
  $("#skip-auth").checked = c.skipAuthEndpoints !== false;
  $("#include").value = (c.includeScopes || []).join("\n");
  $("#exclude").value = (c.excludeScopes || []).join("\n");
  $("#auth-headers").value = (c.customAuthHeaderNames || []).join("\n");
  $("#token-keys").value = (c.tokenStorageKeys || []).join("\n");
  $("#volatile").value = (c.volatileFieldPatterns || []).join("\n");
  $("#owner-markers").value = (c.ownerMarkers || []).join("\n");
  $("#csrf-headers").value = (c.csrfHeaderNames || []).join("\n");
}

function renderIdentities() {
  const host = $("#sessions");
  host.innerHTML = "";
  const c = state.config;
  for (const id of state.identities) {
    const isA = id.id === c.browsingIdentityId;
    const isB = id.id === c.replayIdentityId;
    const pill = document.createElement("span");
    pill.className = "pill" + (isA ? " browsing" : "");
    pill.title = summarize(id);

    const main = document.createElement("span");
    main.className = "pill-main";
    main.title = "Browse as this identity (A)";
    main.innerHTML =
      `<span class="dot" style="background:${id.color}"></span>` +
      esc(id.label || "untitled") +
      (isA ? ` <span class="role-tag a">A · browsing</span>` : "") +
      (isB ? ` <span class="role-tag b">B · replay</span>` : "");
    main.addEventListener("click", async () => { state = await send("AZR_SET_BROWSING", { id: id.id }); renderAll(); });
    pill.appendChild(main);

    if (!isA && !isB) {
      const setB = document.createElement("span");
      setB.className = "set-b";
      setB.textContent = "→B";
      setB.title = "Set as replay target (B)";
      setB.addEventListener("click", async (e) => { e.stopPropagation(); state = await send("AZR_SET_REPLAY", { id: id.id }); renderAll(); });
      pill.appendChild(setB);
    }

    const edit = document.createElement("span");
    edit.className = "edit";
    edit.textContent = "✎";
    edit.title = "Edit this identity";
    edit.addEventListener("click", (e) => { e.stopPropagation(); editIdentity(id.id); });
    pill.appendChild(edit);

    const del = document.createElement("span");
    del.className = "del";
    del.textContent = "🗑";
    del.title = "Delete this identity";
    del.addEventListener("click", (e) => {
      e.stopPropagation();
      if (confirm(`Delete identity "${id.label || "untitled"}"?`)) removeIdentity(id.id);
    });
    pill.appendChild(del);

    host.appendChild(pill);
  }

  const add = document.createElement("button");
  add.className = "pill add";
  add.textContent = "+ Add";
  add.title = "Add an identity manually";
  add.addEventListener("click", addIdentity);
  host.appendChild(add);

  if (state.identities.filter((i) => hasCredentials(i)).length === 0) {
    const tip = document.createElement("span");
    tip.className = "label";
    tip.textContent = "- log in, then + Capture";
    host.appendChild(tip);
  }

  $("#clear-identities").classList.toggle("hidden", state.identities.length === 0);
}

const VERDICTS = ["all", "BYPASSED", "UNCLEAR", "ENFORCED", "PENDING"];
function renderVerdictChips() {
  const host = $("#verdict-chips");
  host.innerHTML = "";
  const counts = {};
  for (const r of state.records) counts[r.verdict] = (counts[r.verdict] || 0) + 1;
  for (const v of VERDICTS) {
    const chip = document.createElement("span");
    chip.className = "chip" + (filter.verdict === v ? " active" : "");
    const n = v === "all" ? state.records.length : counts[v] || 0;
    chip.innerHTML = `${v === "all" ? "All" : v}<span class="count">${n}</span>`;
    chip.addEventListener("click", () => { filter.verdict = v; renderVerdictChips(); renderRecords(); });
    host.appendChild(chip);
  }
}

function visibleRecords() {
  return state.records.filter((r) => {
    if (filter.verdict !== "all" && r.verdict !== filter.verdict) return false;
    if (filter.search) {
      const hay = `${r.method} ${r.url}`.toLowerCase();
      if (!hay.includes(filter.search)) return false;
    }
    return true;
  });
}

function renderRecords() {
  const host = $("#findings");
  host.innerHTML = "";

  const captured = state.identities.filter((i) => hasCredentials(i));
  if (captured.length < 2) {
    const lead = captured.length === 0
      ? "<b>No identities captured yet.</b>"
      : "<b>1 identity captured.</b> Detection needs two to compare - capture a second.";
    host.innerHTML = `<div class="empty">
      ${lead}<br/><br/>
      <b>1.</b> Log into the target as account A → <b>+ Capture</b>.<br/>
      <b>2.</b> <b>Switch user</b> (safe), log in as account B → capture again.<br/>
      <b>3.</b> Browse as A - GET requests auto-replay as B and unauthenticated.
    </div>`;
    return;
  }

  const rows = visibleRecords();
  if (rows.length === 0) {
    host.innerHTML = `<div class="empty">
      In scope: <span class="host">${esc((state.config.includeScopes || []).join(", ") || "(nothing yet)")}</span><br/>
      Browse the target and interact - findings appear here.<br/>
      Write requests (POST/PUT/PATCH/DELETE) are queued with a manual <b>Replay</b> button.
    </div>`;
    return;
  }

  for (const r of rows) host.appendChild(renderRecord(r));
  updateSeqBar();
}

/* ------------------------------------------------- sequence replay (flow) */

function updateSeqBar() {
  // drop ids that are no longer present
  for (const id of [...selected]) if (!state.records.some((r) => r.id === id)) selected.delete(id);
  const bar = $("#seqbar");
  const n = selected.size;
  bar.classList.toggle("hidden", n === 0 || view.mode !== "records");
  $("#seq-count").textContent = `${n} selected`;
}

async function replaySequence() {
  const ids = state.records
    .filter((r) => selected.has(r.id))
    .sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0))
    .map((r) => r.id);
  if (!ids.length) return;
  const writes = state.records.filter((r) => selected.has(r.id) && r.isStateChanging).length;
  if (writes && !confirm(
    `${writes} of the selected requests are state-changing (write) and will run for real ` +
    `as A, B, and unauthenticated. Continue?`
  )) return;

  const btn = $("#seq-run");
  btn.disabled = true;
  btn.textContent = "Replaying…";
  try {
    const result = await send("AZR_REPLAY_SEQUENCE", { ids });
    state = result;
    renderRecords();
    toast(`Replayed ${result.sequenced} requests as a sequence (cookies shared between steps).`, "success");
  } catch (e) {
    toast(String(e.message || e), "danger");
  } finally {
    btn.disabled = false;
    btn.textContent = "Replay as sequence";
  }
}

/* -------------------------------------------------------- findings export */

function exportReport() {
  const rows = visibleRecords();
  if (!rows.length) return toast("No findings to export.", "warning");
  const md = buildMarkdownReport(rows);
  const blob = new Blob([md], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `authz-findings-${new Date().toISOString().replace(/[:.]/g, "-")}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  toast(`Exported ${rows.length} finding${rows.length > 1 ? "s" : ""} to Markdown.`, "success");
}

function buildMarkdownReport(rows) {
  const order = { BYPASSED: 0, UNCLEAR: 1, PENDING: 2, ENFORCED: 3 };
  const sorted = [...rows].sort(
    (a, b) => (order[a.verdict] ?? 9) - (order[b.verdict] ?? 9) || (b.createdAt || 0) - (a.createdAt || 0)
  );
  const counts = {};
  for (const r of rows) counts[r.verdict] = (counts[r.verdict] || 0) + 1;

  const out = [];
  out.push("# AuthZ Replayer findings", "");
  out.push(`Generated ${new Date().toLocaleString()}`, "");
  out.push(`Scope: ${(state.config.includeScopes || []).join(", ") || "(none)"}`, "");
  out.push("Summary: " + ["BYPASSED", "UNCLEAR", "ENFORCED", "PENDING"].map((v) => `${counts[v] || 0} ${v}`).join(" · "), "");
  out.push("> For authorized security testing only.", "");

  for (const r of sorted) {
    out.push(`## ${r.verdict || "PENDING"} - ${r.method} ${r.path}`, "");
    out.push(`- URL: \`${r.url}\``);
    out.push(`- Captured: ${fmtFull(r.createdAt)}`);
    if (r.kind === "graphql") out.push(`- GraphQL ${r.isStateChanging ? "mutation" : "query"}`);
    out.push(`- Baseline (A) status: ${r.baselineStatus ?? "-"}`, "");
    reportLane(out, "Original (A)", r.original);
    reportLane(out, "Replay (B)", r.replayB);
    reportLane(out, "Unauthenticated", r.unauth);
    if (r.replayB && !r.replayB.pending && !r.replayB.error) {
      out.push("Replay (B) as cURL:", "```bash");
      out.push(toCurl({ method: r.method, url: r.url, headers: r.replayB.reqHeaders, body: r.replayB.reqBody }));
      out.push("```", "");
    }
  }
  return out.join("\n");
}

function reportLane(out, title, lane) {
  if (!lane || lane.pending) {
    out.push(`**${title}:** not run`, "");
    return;
  }
  const v = lane.verdict?.verdict;
  out.push(`**${title}:** ${lane.error ? "ERROR " + lane.error : lane.status}${v ? " - " + v : ""}`);
  if (lane.verdict?.reason) out.push(`> ${lane.verdict.reason}`);
  out.push("");
}

function originalChip(lane) {
  if (!lane) return `<span class="lane-chip">A -</span>`;
  if (lane.pending) return `<span class="lane-chip">A …</span>`;
  return `<span class="lane-chip">A ${lane.status || "ERR"}</span>`;
}

function laneChip(label, lane) {
  if (!lane) return `<span class="lane-chip">${label} -</span>`;
  if (lane.pending) return `<span class="lane-chip">${label} …</span>`;
  const v = lane.verdict?.verdict;
  const cls = v === "BYPASSED" ? "bad" : v === "ENFORCED" ? "ok" : v === "UNCLEAR" ? "warn" : "";
  return `<span class="lane-chip ${cls}">${label} ${lane.status || "ERR"}</span>`;
}

function renderRecord(r) {
  const wrap = document.createElement("div");
  wrap.className = "finding " + (r.verdict || "PENDING");

  const head = document.createElement("div");
  head.className = "finding-head";
  head.innerHTML =
    `<span class="method ${esc(r.method)}">${esc(r.method)}</span>` +
    `<span class="badge ${r.verdict || "PENDING"}">${r.verdict || "PENDING"}</span>` +
    `<span class="path" title="${esc(r.url)}">${esc(r.path)}</span>` +
    (r.kind === "graphql" ? `<span class="gql-tag" title="GraphQL ${r.isStateChanging ? "mutation" : "query"}">gql${r.isStateChanging ? "·mut" : ""}</span>` : "") +
    `<span class="time" title="${esc(fmtFull(r.createdAt))}">${esc(fmtTime(r.createdAt))}</span>` +
    `<span class="lane-chips">${originalChip(r.original)}${laneChip("B", r.replayB)}${laneChip("U", r.unauth)}</span>`;
  head.addEventListener("click", () => {
    if (expanded.has(r.id)) expanded.delete(r.id);
    else expanded.add(r.id);
    renderRecords();
  });

  const check = document.createElement("input");
  check.type = "checkbox";
  check.className = "seq-check";
  check.checked = selected.has(r.id);
  check.title = "Select for sequence replay (cookies shared across selected steps)";
  check.addEventListener("click", (e) => {
    e.stopPropagation();
    if (check.checked) selected.add(r.id);
    else selected.delete(r.id);
    updateSeqBar();
  });
  head.insertBefore(check, head.firstChild);
  wrap.appendChild(head);

  if (expanded.has(r.id)) wrap.appendChild(renderDetail(r));
  return wrap;
}

function renderDetail(r) {
  const body = document.createElement("div");
  body.className = "finding-body";
  body.innerHTML = `<div class="host">${esc(r.host)} · baseline ${r.baselineStatus || "-"} · ${esc(fmtFull(r.createdAt))}</div>`;

  const notReplayed = !r.replayB && !r.unauth;
  if (r.isStateChanging) {
    const warn = document.createElement("div");
    warn.className = "warn-box";
    warn.innerHTML =
      `<b>State-changing request.</b> Replaying re-issues it as A, B, and unauthenticated - ` +
      `it may create, modify, delete, email, or charge.` +
      `<div class="warn-note">Only run on targets you're authorized to test.</div>`;
    body.appendChild(warn);
  }

  const actions = document.createElement("div");
  actions.className = "override";
  const replayBtn = document.createElement("button");
  replayBtn.className = "btn tiny " + (r.isStateChanging ? "danger" : "");
  replayBtn.textContent = notReplayed ? (r.isStateChanging ? "Replay as B + unauth" : "Run replay") : "Re-run";
  replayBtn.addEventListener("click", async () => {
    replayBtn.disabled = true;
    replayBtn.textContent = "Replaying…";
    try { state = await send("AZR_REPLAY_RECORD", { id: r.id }); renderRecords(); }
    catch (e) { toast(String(e.message || e), "danger"); }
  });
  actions.appendChild(replayBtn);
  body.appendChild(actions);

  if (!notReplayed) {
    const ov = document.createElement("div");
    ov.className = "override";
    ov.innerHTML = `<span class="label">Override</span>`;
    for (const v of ["BYPASSED", "UNCLEAR", "ENFORCED"]) {
      const b = document.createElement("button");
      b.className = "btn tiny";
      b.textContent = v;
      b.addEventListener("click", async () => { state = await send("AZR_SET_VERDICT", { id: r.id, verdict: v }); renderRecords(); });
      ov.appendChild(b);
    }
    if (r.verdictOverridden) {
      const tag = document.createElement("span");
      tag.className = "label";
      tag.textContent = "(overridden)";
      ov.appendChild(tag);
    }
    body.appendChild(ov);
  }

  const original = r.original;
  if (original) body.appendChild(renderLane(r, original, "Original (A)", true));
  if (r.replayB) body.appendChild(renderLane(r, r.replayB, "Replay (B)", false, original));
  if (r.unauth) body.appendChild(renderLane(r, r.unauth, "Unauthenticated", false, original));
  return body;
}

function renderLane(r, lane, title, isOriginal, original) {
  const el = document.createElement("div");
  el.className = "lane";
  const v = lane.pending ? "PENDING" : lane.verdict?.verdict || "PENDING";

  const top = document.createElement("div");
  top.className = "lane-top";
  top.innerHTML =
    `<span class="dot" style="background:${lane.color || "#888"}"></span>` +
    `<span class="lane-title">${esc(title)}</span>` +
    (isOriginal ? "" : `<span class="badge ${v}">${v}</span>`) +
    `<span style="flex:1"></span>` +
    `<span class="kv">${lane.pending ? "replaying…" : `${lane.error ? "ERR" : lane.status} ${lane.durationMs != null ? "· " + lane.durationMs + "ms" : ""}`}</span>`;
  el.appendChild(top);

  if (lane.pending) return el;

  if (lane.verdict?.reason) {
    const reason = document.createElement("div");
    reason.className = "lane-reason";
    reason.textContent = lane.verdict.reason;
    el.appendChild(reason);
  }
  if (lane.error) {
    const er = document.createElement("div");
    er.className = "lane-reason";
    er.textContent = "Error: " + lane.error;
    el.appendChild(er);
    return el;
  }

  // Request + Response panes (stacked, or side-by-side)
  const panes = document.createElement("div");
  panes.className = "panes " + laneView;

  // ---- Request pane: full HTTP message with line numbers ----
  const reqSec = document.createElement("div");
  reqSec.className = "lane-section pane";
  const reqHead = document.createElement("div");
  reqHead.className = "sub";
  reqHead.innerHTML = `<span>Request</span>`;
  const copywrap = document.createElement("span");
  copywrap.className = "copybtns";
  copywrap.appendChild(makeCopy("cURL", () => toCurl({ method: r.method, url: r.url, headers: lane.reqHeaders, body: lane.reqBody })));
  copywrap.appendChild(makeCopy("fetch", () => toFetch({ method: r.method, url: r.url, headers: lane.reqHeaders, body: lane.reqBody })));
  reqHead.appendChild(copywrap);
  reqSec.appendChild(reqHead);
  reqSec.appendChild(renderCode(buildRequestMessage(r, lane)));
  panes.appendChild(reqSec);

  // ---- Response pane: git-style diff vs A when comparable, else full message ----
  const respSec = document.createElement("div");
  respSec.className = "lane-section pane";
  const respHead = document.createElement("div");
  respHead.className = "sub";
  const showDiff = !isOriginal && original && original.status >= 200 && original.status < 300 && lane.body;
  respHead.innerHTML =
    `<span>Response ${lane.status}${lane.statusText ? " " + esc(lane.statusText) : ""}${lane.redirected ? " (redirected)" : ""}</span>` +
    (showDiff ? `<span class="diff-tag">diff vs A</span>` : "");
  respSec.appendChild(respHead);

  if (showDiff) {
    respSec.appendChild(renderGitDiff(buildResponseMessage(original), buildResponseMessage(lane)));
  } else {
    respSec.appendChild(renderCode(buildResponseMessage(lane)));
  }
  panes.appendChild(respSec);

  el.appendChild(panes);
  return el;
}

function makeCopy(label, getText) {
  const b = document.createElement("button");
  b.className = "link";
  b.textContent = "copy " + label;
  b.addEventListener("click", async (e) => {
    e.stopPropagation();
    try { await navigator.clipboard.writeText(getText()); toast(`Copied ${label}`, "success"); }
    catch { toast("Clipboard blocked", "danger"); }
  });
  return b;
}

function headersToText(headers) {
  return Object.entries(headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n");
}

function buildRequestMessage(r, lane) {
  let s = `${r.method} ${r.url}`;
  const h = headersToText(lane.reqHeaders);
  if (h) s += "\n" + h;
  if (lane.reqBody) s += "\n\n" + prettyBody(lane.reqBody);
  return s;
}

function buildResponseMessage(lane) {
  let s = `HTTP ${lane.status}${lane.statusText ? " " + lane.statusText : ""}`;
  const h = headersToText(lane.headers);
  if (h) s += "\n" + h;
  const b = prettyBody(lane.body);
  s += "\n\n" + (b || "(empty body)");
  return s;
}

// Numbered message view: every line gets a number in a left gutter, and the
// text is syntax-highlighted (start line / headers / JSON body).
function renderCode(text) {
  const pre = document.createElement("pre");
  pre.className = "body code";
  const lines = String(text).split("\n");
  let section = "start";   // start -> headers -> body
  let bodyStarted = false;
  let bodyJson = false;
  lines.forEach((ln, i) => {
    const row = document.createElement("span");
    row.className = "cline";
    const num = document.createElement("span");
    num.className = "lno";
    num.textContent = i + 1;
    const code = document.createElement("span");
    code.className = "ltext";

    let html;
    if (section === "start") {
      html = hlStartLine(ln);
      section = "headers";
    } else if (section === "headers") {
      if (ln === "") { section = "body"; html = ""; }
      else html = hlHeader(ln);
    } else {
      if (!bodyStarted) { bodyStarted = true; bodyJson = /^\s*[{[]/.test(ln); }
      html = ln === "" ? "" : (bodyJson ? hlJsonLine(ln) : esc(ln));
    }
    code.innerHTML = html === "" ? " " : html;
    row.appendChild(num);
    row.appendChild(code);
    pre.appendChild(row);
  });
  return pre;
}

function statusClass(code) {
  const n = +code;
  if (n >= 200 && n < 300) return "s2";
  if (n >= 300 && n < 400) return "s3";
  if (n >= 400) return "s4";
  return "";
}

function hlStartLine(line) {
  const resp = line.match(/^(HTTP)\s+(\d{3})?\s*(.*)$/);
  if (resp) {
    const code = resp[2] || "";
    const tail = resp[3] || "";
    return `<span class="tok-proto">${esc(resp[1])}</span>` +
      (code ? ` <span class="tok-status ${statusClass(code)}">${esc(code)}</span>` : "") +
      (tail ? ` <span class="tok-stext">${esc(tail)}</span>` : "");
  }
  const req = line.match(/^([A-Z]{2,8})\s+(.*)$/);
  if (req) {
    return `<span class="tok-method">${esc(req[1])}</span> <span class="tok-url">${esc(req[2])}</span>`;
  }
  return esc(line);
}

const CRED_HEADERS = new Set([
  "authorization", "proxy-authorization", "authentication", "cookie", "set-cookie",
  "x-api-key", "api-key", "x-auth-token", "x-access-token", "x-csrf-token",
  "x-xsrf-token", "x-session-token", "x-amz-security-token",
]);
// cookie / token names that carry a session or credential
const SESSION_NAME_RE = /sess|sid|token|jwt|auth|csrf|xsrf|secret|api[-_]?key/i;
const JWT_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;

function hlHeader(line) {
  const idx = line.indexOf(":");
  if (idx <= 0) return esc(line);
  const name = line.slice(0, idx);
  const val = line.slice(idx + 1);
  const lname = name.trim().toLowerCase();
  const isCred = CRED_HEADERS.has(lname);
  const nameHtml =
    `<span class="tok-hname${isCred ? " tok-authname" : ""}">${esc(name)}</span>` +
    `<span class="tok-punc">:</span>`;
  if (!val) return nameHtml;

  let valHtml;
  if (lname === "authorization" || lname === "proxy-authorization" || lname === "authentication") {
    valHtml = hlAuthValue(val);
  } else if (lname === "cookie") {
    valHtml = hlCookieValue(val, false);
  } else if (lname === "set-cookie") {
    valHtml = hlCookieValue(val, true);
  } else if (isCred) {
    valHtml = esc(val.match(/^\s*/)[0]) + `<span class="tok-cred">${hlMaybeJwt(val.trimStart())}</span>`;
  } else {
    valHtml = `<span class="tok-hval">${hlMaybeJwt(val)}</span>`;
  }
  return nameHtml + valHtml;
}

// "Bearer <jwt>" / "Basic <b64>" -> scheme + credential token
function hlAuthValue(val) {
  const m = val.match(/^(\s*)(Bearer|Basic|Digest|Token|JWT|Negotiate|Hawk)(\s+)([\s\S]+)$/i);
  if (m) {
    return esc(m[1]) + `<span class="tok-scheme">${esc(m[2])}</span>` + esc(m[3]) + hlCredToken(m[4]);
  }
  return hlCredToken(val);
}

// a single credential token: split JWTs into header.payload.signature
function hlCredToken(s) {
  const lead = s.match(/^\s*/)[0];
  const t = s.slice(lead.length);
  const jwt = t.match(/^(eyJ[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/);
  if (jwt) {
    return esc(lead) +
      `<span class="tok-jwt-h">${esc(jwt[1])}</span><span class="tok-punc">.</span>` +
      `<span class="tok-jwt-p">${esc(jwt[2])}</span><span class="tok-punc">.</span>` +
      `<span class="tok-jwt-s">${esc(jwt[3])}</span>`;
  }
  return esc(lead) + `<span class="tok-cred">${esc(t)}</span>`;
}

// highlight a JWT if one appears anywhere inside an otherwise-plain value
function hlMaybeJwt(s) {
  const m = s.match(JWT_RE);
  if (!m) return esc(s);
  return esc(s.slice(0, m.index)) + hlCredToken(m[0]) + esc(s.slice(m.index + m[0].length));
}

// Cookie / Set-Cookie: name=value pairs; session-ish values colored as creds,
// Set-Cookie attributes (Path, HttpOnly, Secure, Expires...) dimmed.
function hlCookieValue(val, isSetCookie) {
  const lead = val.match(/^\s*/)[0];
  const parts = val.slice(lead.length).split(";");
  const sep = `<span class="tok-punc">;</span>`;
  const html = parts.map((part, i) => {
    const lws = part.match(/^\s*/)[0];
    const seg = part.slice(lws.length);
    const eq = seg.indexOf("=");
    if (isSetCookie && i > 0) {
      if (eq >= 0) {
        return esc(lws) +
          `<span class="tok-cookie-attr">${esc(seg.slice(0, eq))}</span>` +
          `<span class="tok-punc">=</span>` +
          `<span class="tok-cookie-attr">${esc(seg.slice(eq + 1))}</span>`;
      }
      return esc(lws) + `<span class="tok-cookie-attr">${esc(seg)}</span>`;
    }
    if (eq < 0) return esc(part);
    const cname = seg.slice(0, eq);
    const cval = seg.slice(eq + 1);
    const valClass = SESSION_NAME_RE.test(cname) ? "tok-cred" : "tok-cookie-val";
    return esc(lws) +
      `<span class="tok-cookie-name">${esc(cname)}</span>` +
      `<span class="tok-punc">=</span>` +
      `<span class="${valClass}">${hlMaybeJwt(cval)}</span>`;
  }).join(sep);
  return esc(lead) + html;
}

const JSON_TOKEN_RE = /"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\btrue\b|\bfalse\b|\bnull\b|[{}[\]]|,|:/g;
function hlJsonLine(line) {
  let out = "", last = 0, m;
  JSON_TOKEN_RE.lastIndex = 0;
  while ((m = JSON_TOKEN_RE.exec(line))) {
    out += esc(line.slice(last, m.index));
    const t = m[0];
    if (t[0] === '"') {
      const isKey = /^\s*:/.test(line.slice(JSON_TOKEN_RE.lastIndex));
      out += `<span class="${isKey ? "tok-key" : "tok-str"}">${esc(t)}</span>`;
    } else if (/^-?\d/.test(t)) {
      out += `<span class="tok-num">${esc(t)}</span>`;
    } else if (t === "true" || t === "false") {
      out += `<span class="tok-bool">${esc(t)}</span>`;
    } else if (t === "null") {
      out += `<span class="tok-null">${esc(t)}</span>`;
    } else {
      out += `<span class="tok-punc">${esc(t)}</span>`;
    }
    last = JSON_TOKEN_RE.lastIndex;
  }
  out += esc(line.slice(last));
  return out;
}

const DIFF_MAX_LINES = 800;
// git-style unified diff: whole replayed response, single line-number gutter,
// +/- signs. Lines only in A (removed) are shown red with no number.
function renderGitDiff(aText, bText) {
  const pre = document.createElement("pre");
  pre.className = "body gitdiff";
  const a = aText.split("\n").slice(0, DIFF_MAX_LINES);
  const b = bText.split("\n").slice(0, DIFF_MAX_LINES);
  let n = 0;
  for (const part of lineDiff(a, b)) {
    let num = "";
    let sign = " ";
    if (part.type === "ctx") { num = ++n; }
    else if (part.type === "add") { num = ++n; sign = "+"; }
    else { sign = "-"; } // line present in A but not in the replay
    const row = document.createElement("span");
    row.className = "dline " + part.type;
    row.innerHTML = `<span class="dno">${num}</span><span class="dsign">${sign}</span><span class="dtext"></span>`;
    row.querySelector(".dtext").textContent = part.text === "" ? " " : part.text;
    pre.appendChild(row);
  }
  return pre;
}

function lineDiff(a, b) {
  const n = a.length, m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({ type: "ctx", text: a[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ type: "del", text: a[i] }); i++; }
    else { out.push({ type: "add", text: b[j] }); j++; }
  }
  while (i < n) out.push({ type: "del", text: a[i++] });
  while (j < m) out.push({ type: "add", text: b[j++] });
  return out;
}

/* ------------------------------------------------- inline identity editor */

function editIdentity(id) {
  const found = state.identities.find((i) => i.id === id);
  if (!found) return;
  view = { mode: "editor", isNew: false, draft: clone(found) };
  renderAll();
}

function addIdentity() {
  view = { mode: "editor", isNew: true, draft: emptyIdentity() };
  renderAll();
}

function cancelEdit() { view = { mode: "records" }; renderAll(); }

function clone(obj) { return JSON.parse(JSON.stringify(obj)); }

function renderEditor() {
  const host = $("#findings");
  host.innerHTML = "";
  $("#seqbar").classList.add("hidden");
  const d = view.draft;

  const wrap = document.createElement("div");
  wrap.className = "editor-view";

  const head = document.createElement("div");
  head.className = "editor-head";
  const back = document.createElement("button");
  back.className = "btn ghost";
  back.textContent = "← Back";
  back.addEventListener("click", cancelEdit);
  const title = document.createElement("div");
  title.className = "editor-title";
  title.textContent = view.isNew ? "New identity" : `Edit ${d.label || "identity"}`;
  head.appendChild(back);
  head.appendChild(title);
  wrap.appendChild(head);

  wrap.appendChild(buildEditorForm(d));

  const foot = document.createElement("div");
  foot.className = "editor-foot";
  if (!view.isNew) {
    const remove = document.createElement("button");
    remove.className = "btn danger";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => removeIdentity(d.id));
    foot.appendChild(remove);
  }
  const spacer = document.createElement("span");
  spacer.style.flex = "1";
  const cancel = document.createElement("button");
  cancel.className = "btn ghost";
  cancel.textContent = "Cancel";
  cancel.addEventListener("click", cancelEdit);
  const save = document.createElement("button");
  save.className = "btn primary";
  save.textContent = "Save";
  save.addEventListener("click", saveEdit);
  foot.appendChild(spacer);
  foot.appendChild(cancel);
  foot.appendChild(save);
  wrap.appendChild(foot);

  host.appendChild(wrap);
}

function buildEditorForm(identity) {
  const el = document.createElement("div");
  el.className = "editor";
  el.innerHTML = `
    <div class="field"><div class="sub">Label</div><input type="text" class="f-label" placeholder="A - admin" value="${esc(identity.label)}" /></div>
    <div class="field"><div class="sub">Scope domain</div><input type="text" class="f-scope" placeholder="https://app.example.com" value="${esc(identity.scopeDomain || "")}" /></div>
    ${identity.capturedAt ? `<div class="captured-note">Captured ${esc(new Date(identity.capturedAt).toLocaleString())}</div>` : ""}

    <div class="sub" style="margin-top:6px">Cookies</div>
    <div class="f-cookies"></div>
    <button class="link f-add-cookie">+ add cookie</button>

    <div class="sub" style="margin-top:6px">Auth headers</div>
    <div class="f-headers"></div>
    <button class="link f-add-header">+ add header</button>

    <div class="sub" style="margin-top:6px">Token storage (localStorage / sessionStorage)</div>
    <div class="f-tokens"></div>
    <button class="link f-add-token">+ add token</button>`;

  const cookiesHost = el.querySelector(".f-cookies");
  (identity.cookies || []).forEach((c) => cookiesHost.appendChild(cookieRow(c)));
  el.querySelector(".f-add-cookie").addEventListener("click", () => cookiesHost.appendChild(cookieRow({})));

  const headersHost = el.querySelector(".f-headers");
  Object.entries(identity.authHeaders || {}).forEach(([k, v]) => headersHost.appendChild(headerRow(k, v)));
  el.querySelector(".f-add-header").addEventListener("click", () => headersHost.appendChild(headerRow("", "")));

  const tokensHost = el.querySelector(".f-tokens");
  (identity.tokenStorage || []).forEach((t) => tokensHost.appendChild(tokenRow(t)));
  el.querySelector(".f-add-token").addEventListener("click", () => tokensHost.appendChild(tokenRow({})));

  return el;
}

function cookieRow(c) {
  const row = document.createElement("div");
  row.className = "row4 cookie-row";
  row.innerHTML = `
    <input type="text" class="c-name" placeholder="name" value="${esc(c.name || "")}" />
    <input type="text" class="c-value" placeholder="value" value="${esc(c.value || "")}" />
    <input type="text" class="c-domain" placeholder="domain" value="${esc(c.domain || "")}" />
    <input type="text" class="c-path" placeholder="/" value="${esc(c.path || "/")}" />
    <button class="x">×</button>`;
  row.querySelector(".x").addEventListener("click", () => row.remove());
  return row;
}

function headerRow(name, value) {
  const row = document.createElement("div");
  row.className = "row2 header-row";
  row.innerHTML = `
    <input type="text" class="h-name" placeholder="Authorization" value="${esc(name)}" />
    <input type="text" class="h-value" placeholder="Bearer …" value="${esc(value)}" />
    <button class="x">×</button>`;
  row.querySelector(".x").addEventListener("click", () => row.remove());
  return row;
}

function tokenRow(t) {
  const row = document.createElement("div");
  row.className = "row3 token-row";
  row.innerHTML = `
    <input type="text" class="t-key" placeholder="access_token" value="${esc(t.key || "")}" />
    <input type="text" class="t-value" placeholder="value" value="${esc(t.value || "")}" />
    <select class="t-store">
      <option value="local"${t.store === "session" ? "" : " selected"}>local</option>
      <option value="session"${t.store === "session" ? " selected" : ""}>session</option>
    </select>
    <button class="x">×</button>`;
  row.querySelector(".x").addEventListener("click", () => row.remove());
  return row;
}

async function saveEdit() {
  const el = $("#findings .editor");
  if (!el) return;
  const d = view.draft;

  const cookies = [...el.querySelectorAll(".cookie-row")]
    .map((r) => ({
      name: r.querySelector(".c-name").value.trim(),
      value: r.querySelector(".c-value").value,
      domain: r.querySelector(".c-domain").value.trim(),
      path: r.querySelector(".c-path").value.trim() || "/",
    }))
    .filter((c) => c.name);

  const authHeaders = {};
  for (const r of el.querySelectorAll(".header-row")) {
    const name = r.querySelector(".h-name").value.trim();
    if (name) authHeaders[name] = r.querySelector(".h-value").value;
  }

  const tokenStorage = [...el.querySelectorAll(".token-row")]
    .map((r) => ({
      key: r.querySelector(".t-key").value.trim(),
      value: r.querySelector(".t-value").value,
      store: r.querySelector(".t-store").value,
    }))
    .filter((t) => t.key);

  const updated = {
    id: d.id,
    color: d.color,
    label: el.querySelector(".f-label").value.trim() || d.label || "identity",
    scopeDomain: el.querySelector(".f-scope").value.trim(),
    cookies,
    authHeaders,
    tokenStorage,
    capturedAt: d.capturedAt || null,
  };
  const list = view.isNew
    ? [...state.identities, updated]
    : state.identities.map((i) => (i.id === d.id ? updated : i));
  state = await send("AZR_SAVE_IDENTITIES", { identities: list });
  view = { mode: "records" };
  renderAll();
  toast(`Saved ${updated.label}`, "success");
}

async function removeIdentity(id) {
  const next = state.identities.filter((i) => i.id !== id);
  state = await send("AZR_SAVE_IDENTITIES", { identities: next });
  view = { mode: "records" };
  renderAll();
}

/* ---------------------------------------------------------------- utils -- */

let toastTimer = null;
function toast(message, tone = "info") {
  let el = document.getElementById("toast");
  if (!el) { el = document.createElement("div"); el.id = "toast"; document.body.appendChild(el); }
  const colors = {
    success: ["rgba(86,210,127,.14)", "var(--green)"],
    danger: ["rgba(255,88,116,.14)", "var(--red)"],
    warning: ["rgba(255,180,84,.14)", "var(--amber)"],
    info: ["rgba(189,242,78,.14)", "var(--accent)"],
  }[tone] || ["rgba(189,242,78,.14)", "var(--accent)"];
  el.style.background = colors[0];
  el.style.color = colors[1];
  el.textContent = message;
  el.style.display = "block";
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.style.display = "none"), 4500);
}

function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function fmtFull(ts) {
  if (!ts) return "";
  return new Date(ts).toLocaleString();
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
