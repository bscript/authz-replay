/**
 * AuthZ Replayer - background service worker (the engine).
 *
 * For authorized security testing only.
 *
 * Pipeline (no DevTools, no proxy):
 *   1. chrome.webRequest watches traffic, keeping only requests whose URL is in
 *      the user-configured scope (default: nothing - you must add a target, or
 *      capture a session which auto-adds its origin).
 *   2. GET/HEAD requests are auto-replayed in three lanes:
 *        Original (A)  - the browsing identity, re-issued so we have a body to diff
 *        Replay (B)    - the replay identity (lower-priv / attacker)
 *        Unauth        - all credentials stripped
 *      POST/PUT/PATCH/DELETE are NEVER auto-fired - they are queued and only run
 *      when the tester clicks "Replay" on that row (they can modify/delete data).
 *   3. Each lane's response body is normalized + compared to the original and the
 *      lane is classified ENFORCED / BYPASSED / UNCLEAR.
 *   4. Records are persisted to chrome.storage.session; the panel renders them live.
 *
 * Cookies for a replay identity are injected via a one-time, nonce-scoped
 * declarativeNetRequest rule (fetch can't set the Cookie header). The live cookie
 * jar is never touched. The unauthenticated lane sends no credentials at all.
 */

import {
  loadIdentities,
  saveIdentities,
  identityFromCapture,
  hasCredentials,
} from "../lib/identities.js";
import { inScope, originPattern } from "../lib/scope.js";
import { classify, worstVerdict, DEFAULT_VOLATILE_PATTERNS } from "../lib/classify.js";
import { analyzeRequest } from "../lib/request.js";

const MAX_BODY_BYTES = 512 * 1024;
const MAX_RECORDS = 200;

const CONFIG_KEY = "azr.config";
const RECORDS_KEY = "azr.records";

const SELF_ORIGIN = `chrome-extension://${chrome.runtime.id}`;
const WATCHED_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);

const DEFAULT_CONFIG = {
  enabled: true,
  autoReplayGet: true,
  skipAuthEndpoints: true,
  includeScopes: [],
  excludeScopes: [],
  browsingIdentityId: null,
  replayIdentityId: null,
  customAuthHeaderNames: [],
  tokenStorageKeys: [],
  volatileFieldPatterns: DEFAULT_VOLATILE_PATTERNS,
  ownerMarkers: [],
  // CSRF auto-substitution: when replaying as B, any of these request headers is
  // rewritten to B's own token (read from B's CSRF cookie, else a captured CSRF
  // header). Clear the list to disable.
  csrfHeaderNames: [
    "x-csrf-token", "x-xsrf-token", "x-csrftoken", "csrf-token", "x-csrf",
    "requestverificationtoken", "anti-csrf-token",
  ],
  csrfCookieNames: ["xsrf-token", "csrf-token", "csrftoken", "_csrf", "csrf"],
};

// ---- in-memory caches (rebuilt on each worker wake) -----------------------
let identities = [];
let config = { ...DEFAULT_CONFIG };
let records = [];
let loaded = false;

const lastHeadersByOrigin = Object.create(null); // origin -> { headerName: value }
const pending = new Map(); // webRequest requestId -> partial captured request

async function ensureLoaded() {
  if (loaded) return;
  identities = await loadIdentities();
  const local = await chrome.storage.local.get(CONFIG_KEY);
  config = { ...DEFAULT_CONFIG, ...(local[CONFIG_KEY] || {}) };
  const session = await chrome.storage.session.get(RECORDS_KEY);
  records = session[RECORDS_KEY] || [];
  ensureRoles();
  loaded = true;
}
ensureLoaded().catch(() => {});

// Let the on-page banner (content script) read live records for its counter.
chrome.storage.session
  .setAccessLevel?.({ accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" })
  .catch(() => {});

// Clicking the toolbar icon opens the side-panel drawer on the right.
chrome.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: true }).catch(() => {});
chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: true }).catch(() => {});
});

/* ----------------------------------------------------------- webRequest -- */

chrome.webRequest.onBeforeRequest.addListener(
  (d) => {
    if (!WATCHED_METHODS.has(d.method)) return;
    if (d.initiator === SELF_ORIGIN) return; // our own replay
    if (d.url.includes("azr_nonce=")) return; // our own replay (marker)
    if (!inScope(d.url, config)) return;
    if (isStaticAsset(d.url, d.type)) return; // skip js/css/images/fonts - irrelevant to authz
    if (config.skipAuthEndpoints && isAuthEndpoint(d.url)) return; // login/logout etc. - replaying them is meaningless
    pending.set(d.requestId, {
      method: d.method,
      url: d.url,
      body: extractBody(d.requestBody),
      headers: {},
      startedAt: Date.now(),
    });
    if (pending.size > 1000) pending.delete(pending.keys().next().value);
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["requestBody"]
);

chrome.webRequest.onSendHeaders.addListener(
  (d) => {
    recordHeaders(d);
    const p = pending.get(d.requestId);
    if (p) p.headers = headerArrayToObject(d.requestHeaders);
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["requestHeaders", "extraHeaders"]
);

chrome.webRequest.onCompleted.addListener(
  (d) => {
    const p = pending.get(d.requestId);
    if (!p) return;
    pending.delete(d.requestId);
    p.baselineStatus = d.statusCode;
    onCaptured(p).catch(() => {});
  },
  { urls: ["http://*/*", "https://*/*"] }
);

chrome.webRequest.onErrorOccurred.addListener((d) => pending.delete(d.requestId), {
  urls: ["http://*/*", "https://*/*"],
});

// Capture Set-Cookie from our OWN replay responses (identified by the azr_nonce
// marker) so a sequence replay can carry cookies set in step 1 into step 2.
// fetch() in a service worker hides Set-Cookie, so we read it here instead.
const replaySetCookies = new Map(); // nonce -> [rawSetCookieValue]
chrome.webRequest.onHeadersReceived.addListener(
  (d) => {
    const i = d.url.indexOf("azr_nonce=");
    if (i < 0) return;
    const nonce = d.url.slice(i + "azr_nonce=".length).split(/[&#]/)[0];
    const got = [];
    for (const h of d.responseHeaders || []) {
      if ((h.name || "").toLowerCase() === "set-cookie" && h.value) got.push(h.value);
    }
    if (got.length) replaySetCookies.set(nonce, (replaySetCookies.get(nonce) || []).concat(got));
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["responseHeaders", "extraHeaders"]
);

function recordHeaders(d) {
  try {
    const origin = new URL(d.url).origin;
    const wanted = new Set([
      "authorization",
      ...config.customAuthHeaderNames.map((n) => n.toLowerCase()),
      ...(config.csrfHeaderNames || []).map((n) => n.toLowerCase()),
    ]);
    for (const h of d.requestHeaders || []) {
      if (h.value && wanted.has((h.name || "").toLowerCase())) {
        lastHeadersByOrigin[origin] = lastHeadersByOrigin[origin] || {};
        lastHeadersByOrigin[origin][h.name] = h.value;
      }
    }
  } catch {
    /* ignore */
  }
}

function headerArrayToObject(arr) {
  const o = {};
  for (const h of arr || []) {
    if (h && h.name && o[h.name] === undefined) o[h.name] = h.value;
  }
  return o;
}

// Static assets are noise for access-control testing - drop them by resource
// type and by file extension (covers dev-server .tsx/.ts/.jsx/.scss too).
const ASSET_TYPES = new Set([
  "stylesheet", "script", "image", "font", "media", "csp_report", "ping", "beacon", "object",
]);
const ASSET_EXT = /\.(css|scss|sass|less|js|mjs|cjs|jsx|ts|tsx|map|png|jpe?g|gif|svg|webp|avif|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mov|mp3|wav|ogg)$/i;

function isStaticAsset(url, type) {
  if (type && ASSET_TYPES.has(type)) return true;
  try {
    return ASSET_EXT.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

// Authentication endpoints (login / logout / token / oauth ...). Replaying these
// as another identity is meaningless and just adds noise, so they're skipped by
// default (toggle in Settings). Matched as whole path segments to avoid hitting
// things like /authors or /sessions-report.
const AUTH_SEGMENT =
  /(?:^|\/)(?:login|log-?in|logout|log-?out|signin|sign-?in|signout|sign-?out|signup|sign-?up|register|authenticate|auth|oauth2?|sso|token|saml|mfa|otp|forgot-?password|reset-?password)(?:\/|$)/i;

function isAuthEndpoint(url) {
  try {
    return AUTH_SEGMENT.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

function extractBody(requestBody) {
  if (!requestBody) return null;
  if (requestBody.raw && requestBody.raw.length) {
    try {
      const dec = new TextDecoder("utf-8");
      return requestBody.raw.map((part) => (part.bytes ? dec.decode(part.bytes) : "")).join("");
    } catch {
      return null;
    }
  }
  if (requestBody.formData) {
    const params = new URLSearchParams();
    for (const key of Object.keys(requestBody.formData)) {
      for (const value of requestBody.formData[key]) params.append(key, value);
    }
    return params.toString();
  }
  return null;
}

/* ------------------------------------------------------ capture -> lanes -- */

async function onCaptured(p) {
  await ensureLoaded();
  if (!config.enabled) return;
  if (!inScope(p.url, config)) return;
  // Need at least two captured identities to compare - one to browse as and one
  // to replay as. With a single identity there's nothing to test against.
  if (identities.filter((i) => hasCredentials(i)).length < 2) return;

  // GraphQL-aware: a GraphQL query is a read sent as POST - don't treat it as a
  // state-changing write (which would block auto-replay and skew the verdict).
  const { kind, isWrite } = analyzeRequest({ method: p.method, url: p.url, body: p.body });
  const record = upsertRecord(p, isWrite, kind);
  await persist();

  if (!isWrite && config.autoReplayGet) {
    await runLanes(record, { includeOriginal: true });
  }
}

function upsertRecord(p, isWrite, kind) {
  let parsed;
  try {
    parsed = new URL(p.url);
  } catch {
    parsed = { host: "", pathname: p.url, search: "" };
  }
  const existing = records.find((r) => r.method === p.method && r.url === p.url);
  if (existing) {
    existing.baselineStatus = p.baselineStatus;
    existing.reqHeaders = p.headers;
    existing.reqBody = p.body || "";
    existing.kind = kind;
    existing.isStateChanging = isWrite;
    existing.createdAt = Date.now();
    records = [existing, ...records.filter((r) => r !== existing)];
    return existing;
  }
  const record = {
    id: `r_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`,
    method: p.method,
    url: p.url,
    host: parsed.host,
    path: parsed.pathname + parsed.search,
    reqHeaders: p.headers,
    reqBody: p.body || "",
    baselineStatus: p.baselineStatus,
    kind,
    original: null,
    replayB: null,
    unauth: null,
    verdict: "PENDING",
    verdictOverridden: false,
    isStateChanging: isWrite,
    createdAt: Date.now(),
  };
  records = [record, ...records].slice(0, MAX_RECORDS);
  return record;
}

async function runLanes(record, { includeOriginal = true } = {}) {
  ensureRoles();
  const A = getIdentity(config.browsingIdentityId);
  const B = getIdentity(config.replayIdentityId);

  record.original = includeOriginal && A ? pendingLane(A) : null;
  record.replayB = B ? pendingLane(B) : null;
  record.unauth = pendingLane(null);
  record.verdict = "PENDING";
  await persist();

  if (includeOriginal && A) {
    record.original = await runLane(record, A);
    await persist();
  }
  if (B) {
    record.replayB = await runLane(record, B);
    await persist();
  }
  record.unauth = await runLane(record, null);
  classifyRecord(record);
  await persist();
  updateBadge();
}

function pendingLane(identity) {
  return {
    identityId: identity ? identity.id : null,
    label: identity ? identity.label : "No-auth",
    color: identity ? identity.color : "#8a8a8a",
    pending: true,
  };
}

// Replay a set of records in order as one flow. Each lane (A / B / unauth) keeps
// its own cookie jar that accumulates Set-Cookie across steps, so multi-step
// flows (grab a token / session in step 1, use it in step 2) replay correctly.
async function runSequence(ids) {
  ensureRoles();
  const A = getIdentity(config.browsingIdentityId);
  const B = getIdentity(config.replayIdentityId);
  const jars = {
    A: identityCookieMap(A),
    B: identityCookieMap(B),
    U: {},
  };
  const ordered = ids
    .map((id) => records.find((r) => r.id === id))
    .filter(Boolean)
    .sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));

  for (const record of ordered) {
    record.original = A ? pendingLane(A) : null;
    record.replayB = B ? pendingLane(B) : null;
    record.unauth = pendingLane(null);
    record.verdict = "PENDING";
    record.sequenced = true;
    await persist();

    if (A) {
      record.original = await runLane(record, A, { jar: jars.A });
      await persist();
    }
    if (B) {
      record.replayB = await runLane(record, B, { jar: jars.B });
      await persist();
    }
    record.unauth = await runLane(record, null, { jar: jars.U });
    classifyRecord(record);
    await persist();
  }
  updateBadge();
  return ordered.length;
}

function classifyRecord(record) {
  const orig =
    record.original && record.original.status >= 200 && record.original.status < 300
      ? record.original
      : null;
  const patterns = config.volatileFieldPatterns;
  const markers = config.ownerMarkers;
  const method = record.method;
  const isWrite = record.isStateChanging;
  const kind = record.kind;
  if (record.replayB && !record.replayB.pending) {
    record.replayB.verdict = classify({ original: orig, lane: record.replayB, isUnauth: false, patterns, method, markers, isWrite, kind });
  }
  if (record.unauth && !record.unauth.pending) {
    record.unauth.verdict = classify({ original: orig, lane: record.unauth, isUnauth: true, patterns, method, markers, isWrite, kind });
  }
  if (!record.verdictOverridden) {
    record.verdict = worstVerdict([record.replayB?.verdict?.verdict, record.unauth?.verdict?.verdict]);
  }
}

function reclassifyAll() {
  for (const record of records) {
    const hasResult =
      (record.replayB && !record.replayB.pending) || (record.unauth && !record.unauth.pending);
    if (hasResult) classifyRecord(record);
  }
}

async function persist() {
  await chrome.storage.session.set({ [RECORDS_KEY]: records.slice(0, MAX_RECORDS) });
}

function updateBadge() {
  const count = records.filter((r) => r.verdict === "BYPASSED").length;
  chrome.action.setBadgeText({ text: count ? String(count) : "" });
  if (count) chrome.action.setBadgeBackgroundColor({ color: "#f06c75" });
}

/* ----------------------------------------------------- replay engine ----- */

const STRIPPED_REQUEST_HEADERS = new Set([
  "host", "connection", "content-length", "transfer-encoding", "keep-alive",
  "upgrade", "te", "trailer", "accept-encoding", "proxy-authorization",
  "cookie", "authorization", "origin", "referer",
]);

const REPLAY_RESOURCE_TYPES = [
  "xmlhttprequest", "other", "sub_frame", "main_frame", "script",
  "image", "font", "stylesheet", "media", "websocket", "csp_report",
];

// flow (optional): { jar } - a shared cookie map for sequence replay. When set,
// the request uses the jar's cookies (seeded from the identity) and Set-Cookie
// from the response is merged back into the jar for the next step.
async function runLane(record, identity, flow = null) {
  const started = performance.now();
  const customAuth = new Set(config.customAuthHeaderNames.map((n) => n.toLowerCase()));
  const csrfNames = new Set((config.csrfHeaderNames || []).map((n) => n.toLowerCase()));

  // The cookie map for this lane: a flow jar (sequence) or the identity's own.
  const cookieMap = flow ? flow.jar : identity ? identityCookieMap(identity) : {};

  const fetchHeaders = {}; // sent to the server (Cookie excluded - set via DNR)
  const displayHeaders = {}; // for copy-as-cURL / fetch (includes Cookie)
  const origCsrfHeaderNames = []; // CSRF headers from the original req (orig casing)
  for (const [name, value] of Object.entries(record.reqHeaders || {})) {
    const ln = (name || "").toLowerCase();
    if (!ln || ln.startsWith(":")) continue;
    if (STRIPPED_REQUEST_HEADERS.has(ln)) continue;
    if (customAuth.has(ln)) continue; // replaced by the identity's value
    if (csrfNames.has(ln)) { origCsrfHeaderNames.push(name); continue; } // set below
    fetchHeaders[name] = value;
    displayHeaders[name] = value;
  }
  if (identity) {
    for (const [n, v] of Object.entries(identity.authHeaders || {})) {
      if (csrfNames.has((n || "").toLowerCase())) continue; // owned by CSRF logic
      fetchHeaders[n] = v;
      displayHeaders[n] = v;
    }
  }

  // CSRF auto-substitution: rewrite the original request's CSRF header(s) to this
  // identity's own token. Unauthenticated (no token) drops the header entirely.
  if (origCsrfHeaderNames.length) {
    const token = csrfToken(cookieMap, identity, config);
    if (token) {
      for (const name of origCsrfHeaderNames) {
        fetchHeaders[name] = token;
        displayHeaders[name] = token;
      }
    }
  }

  const method = (record.method || "GET").toUpperCase();
  const hasBody = !["GET", "HEAD"].includes(method) && !!record.reqBody;

  const ck = cookieHeaderFromMap(cookieMap);
  if (ck) displayHeaders["Cookie"] = ck;
  const nonce = `azr_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  const url = appendQueryParam(record.url, "azr_nonce", nonce);
  let ruleId = null;
  if (ck) ruleId = await installCookieRule(nonce, ck);

  const base = {
    identityId: identity ? identity.id : null,
    label: identity ? identity.label : "No-auth",
    color: identity ? identity.color : "#8a8a8a",
    reqHeaders: displayHeaders,
    reqBody: hasBody ? record.reqBody : "",
  };

  try {
    const response = await fetch(url, {
      method,
      headers: fetchHeaders,
      body: hasBody ? record.reqBody : undefined,
      credentials: "omit",
      redirect: "follow",
      cache: "no-store",
    });
    const { bodyText, truncated } = await readBody(response);
    const respHeaders = {};
    response.headers.forEach((v, k) => (respHeaders[k] = v));
    // Carry any Set-Cookie into the flow jar for the next step in the sequence.
    if (flow) {
      const raws = replaySetCookies.get(nonce) || [];
      for (const raw of raws) mergeSetCookie(flow.jar, raw);
    }
    replaySetCookies.delete(nonce);
    return {
      ...base,
      status: response.status,
      statusText: response.statusText,
      headers: respHeaders,
      body: bodyText,
      truncated,
      finalUrl: response.url,
      redirected: response.redirected,
      durationMs: Math.round(performance.now() - started),
      error: null,
    };
  } catch (err) {
    replaySetCookies.delete(nonce);
    return { ...base, status: 0, headers: {}, body: "", error: String(err?.message || err) };
  } finally {
    if (ruleId !== null) {
      await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [ruleId] }).catch(() => {});
    }
  }
}

function identityCookieMap(identity) {
  const map = {};
  for (const c of identity?.cookies || []) {
    if (c && c.name) map[c.name] = c.value;
  }
  return map;
}

function cookieHeaderFromMap(map) {
  return Object.entries(map || {})
    .filter(([k]) => k)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
}

// This identity's CSRF token: prefer a double-submit CSRF cookie (most common),
// then fall back to a CSRF value captured from a request header.
function csrfToken(cookieMap, identity, cfg) {
  const cookieNames = new Set((cfg.csrfCookieNames || []).map((n) => n.toLowerCase()));
  for (const [name, value] of Object.entries(cookieMap || {})) {
    if (cookieNames.has((name || "").toLowerCase())) {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }
  const headerNames = new Set((cfg.csrfHeaderNames || []).map((n) => n.toLowerCase()));
  for (const [k, v] of Object.entries(identity?.authHeaders || {})) {
    if (headerNames.has((k || "").toLowerCase())) return v;
  }
  return "";
}

// Merge one Set-Cookie response header into a flow jar.
function mergeSetCookie(jar, raw) {
  const first = String(raw).split(";")[0];
  const eq = first.indexOf("=");
  if (eq < 0) return;
  const name = first.slice(0, eq).trim();
  if (!name) return;
  const value = first.slice(eq + 1).trim();
  if (/(?:^|;)\s*max-age=0\b/i.test(raw) || /expires=[^;]*19[0-9]{2}/i.test(raw)) {
    delete jar[name];
    return;
  }
  jar[name] = value;
}

async function installCookieRule(nonce, cookieValue) {
  const ruleId = Math.floor(Math.random() * 2_000_000) + 1000;
  await chrome.declarativeNetRequest.updateSessionRules({
    addRules: [
      {
        id: ruleId,
        priority: 100,
        action: {
          type: "modifyHeaders",
          requestHeaders: [{ header: "cookie", operation: "set", value: cookieValue }],
        },
        condition: { urlFilter: `azr_nonce=${nonce}`, resourceTypes: REPLAY_RESOURCE_TYPES },
      },
    ],
  });
  return ruleId;
}

async function readBody(response) {
  const ct = (response.headers.get("content-type") || "").toLowerCase();
  const isText = /json|text|xml|javascript|html|csv|x-www-form-urlencoded/.test(ct) || !ct;
  if (!isText) return { bodyText: `[${ct || "binary"} response - body not captured]`, truncated: false };
  const text = await response.text();
  if (text.length > MAX_BODY_BYTES) return { bodyText: text.slice(0, MAX_BODY_BYTES), truncated: true };
  return { bodyText: text, truncated: false };
}

function appendQueryParam(rawUrl, key, value) {
  try {
    const u = new URL(rawUrl);
    u.searchParams.set(key, value);
    return u.toString();
  } catch {
    const sep = rawUrl.includes("?") ? "&" : "?";
    return `${rawUrl}${sep}${key}=${value}`;
  }
}

/* -------------------------------------------------------- identity roles -- */

function getIdentity(id) {
  return identities.find((i) => i.id === id) || null;
}

function ensureRoles() {
  const captured = identities.filter((i) => hasCredentials(i));
  if (!getIdentity(config.browsingIdentityId)) {
    config.browsingIdentityId = captured[0]?.id || null;
  }
  if (
    !getIdentity(config.replayIdentityId) ||
    config.replayIdentityId === config.browsingIdentityId
  ) {
    const other = captured.find((i) => i.id !== config.browsingIdentityId);
    config.replayIdentityId = other?.id || null;
  }
}

async function saveConfig() {
  await chrome.storage.local.set({ [CONFIG_KEY]: config });
}

/* --------------------------------------------------------- message API --- */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: String(error?.message || error) }));
  return true; // async
});

async function handleMessage(message, sender) {
  await ensureLoaded();
  switch (message?.type) {
    case "AZR_GET_STATE":
      return state();

    case "AZR_CAPTURE_IDENTITY":
      return captureIdentity(message.url ?? sender?.tab?.url, message.tabId ?? sender?.tab?.id);

    case "AZR_SAVE_IDENTITIES":
      identities = message.identities;
      await saveIdentities(identities);
      ensureRoles();
      await saveConfig();
      return state();

    case "AZR_SET_CONFIG":
      config = { ...config, ...message.config };
      ensureRoles();
      await saveConfig();
      // Re-classify existing findings so changes to owner markers / volatile
      // patterns take effect immediately, without re-issuing any request.
      reclassifyAll();
      await persist();
      updateBadge();
      return state();

    case "AZR_RECLASSIFY":
      reclassifyAll();
      await persist();
      updateBadge();
      return state();

    case "AZR_SET_BROWSING":
      config.browsingIdentityId = message.id;
      if (config.replayIdentityId === message.id) config.replayIdentityId = null;
      ensureRoles();
      await saveConfig();
      return state();

    case "AZR_SET_REPLAY":
      config.replayIdentityId = message.id;
      if (config.browsingIdentityId === message.id) config.browsingIdentityId = null;
      ensureRoles();
      await saveConfig();
      return state();

    case "AZR_REPLAY_RECORD": {
      const record = records.find((r) => r.id === message.id);
      if (!record) throw new Error("record not found");
      await runLanes(record, { includeOriginal: true });
      return state();
    }

    case "AZR_REPLAY_SEQUENCE": {
      const ids = message.ids || [];
      if (!ids.length) throw new Error("no requests selected");
      const count = await runSequence(ids);
      return { ...state(), sequenced: count };
    }

    case "AZR_SET_VERDICT": {
      const record = records.find((r) => r.id === message.id);
      if (!record) throw new Error("record not found");
      record.verdict = message.verdict;
      record.verdictOverridden = true;
      await persist();
      updateBadge();
      return state();
    }

    case "AZR_SWITCH_USER":
      return switchUser(message.url ?? sender?.tab?.url, message.tabId ?? sender?.tab?.id);

    case "AZR_CLEAR":
      records = [];
      await persist();
      chrome.action.setBadgeText({ text: "" });
      return state();

    default:
      throw new Error("unknown message: " + message?.type);
  }
}

function state() {
  return {
    identities,
    config,
    records: records.slice(0, MAX_RECORDS),
  };
}

/* ----------------------------------------------------------- capture ----- */

async function captureIdentity(url, tabId) {
  if (!url || !/^https?:/i.test(url)) {
    throw new Error("Open a normal http(s) page in the active tab first.");
  }
  const origin = new URL(url).origin;

  const rawCookies = await chrome.cookies.getAll({ url });
  const cookies = rawCookies.map((c) => ({ name: c.name, value: c.value, domain: c.domain, path: c.path }));

  const authHeaders = { ...(lastHeadersByOrigin[origin] || {}) };

  let tokenStorage = [];
  if (config.tokenStorageKeys.length && tabId != null) {
    tokenStorage = await readTokenStorage(tabId, config.tokenStorageKeys).catch(() => []);
  }

  if (!cookies.length && !Object.keys(authHeaders).length && !tokenStorage.length) {
    throw new Error(
      `No cookies, auth header, or configured token found for ${origin}. Log in, click around once, then capture.`
    );
  }

  // auto-add this origin to scope so it works out of the box
  const pattern = originPattern(url);
  if (pattern && !config.includeScopes.includes(pattern)) {
    config.includeScopes = [...config.includeScopes, pattern];
  }

  // Dedupe: if these credentials identify a user we already captured for this
  // origin (same auth token, or same session cookies), refresh that identity
  // instead of adding a duplicate.
  const candidate = { scopeDomain: origin, cookies, authHeaders, tokenStorage };
  const key = identityKey(candidate);
  const existing = identities.find((i) => identityKey(i) === key);

  let identity;
  let refreshed = false;
  if (existing) {
    existing.cookies = cookies;
    existing.authHeaders = authHeaders;
    existing.tokenStorage = tokenStorage;
    existing.scopeDomain = existing.scopeDomain || origin;
    existing.capturedAt = Date.now();
    identity = existing;
    refreshed = true;
    await saveIdentities(identities);
  } else {
    const index = identities.length + 1;
    identity = identityFromCapture({ origin, cookies, authHeaders, tokenStorage, index });
    identities = [...identities, identity];
    await saveIdentities(identities);
  }

  ensureRoles();
  // first capture becomes browsing(A), second becomes replay(B)
  if (!config.browsingIdentityId) config.browsingIdentityId = identity.id;
  else if (!config.replayIdentityId && config.browsingIdentityId !== identity.id) {
    config.replayIdentityId = identity.id;
  }
  await saveConfig();

  return {
    ...state(),
    captured: {
      label: identity.label,
      cookieCount: cookies.length,
      authHeaders: Object.keys(authHeaders),
      tokenCount: tokenStorage.length,
      origin,
      refreshed,
    },
  };
}

// A stable key for "which user is this". Prefer the auth token (bearer / custom
// auth header) since that identifies the user; fall back to session cookies,
// then web-storage tokens. Same key = same identity, so re-capturing refreshes
// instead of duplicating.
function identityKey(id) {
  const origin = id.scopeDomain || "";
  const headers = Object.entries(id.authHeaders || {})
    .map(([k, v]) => `${k.toLowerCase()}:${v}`)
    .sort()
    .join("&");
  if (headers) return `${origin}|h|${headers}`;
  const cookies = (id.cookies || [])
    .map((c) => `${c.name}=${c.value}`)
    .sort()
    .join("&");
  if (cookies) return `${origin}|c|${cookies}`;
  const tokens = (id.tokenStorage || [])
    .map((t) => `${t.store}:${t.key}=${t.value}`)
    .sort()
    .join("&");
  return `${origin}|t|${tokens}`;
}

async function readTokenStorage(tabId, keys) {
  const [{ result } = {}] = await chrome.scripting.executeScript({
    target: { tabId },
    args: [keys],
    func: (wantKeys) => {
      const out = [];
      for (const key of wantKeys) {
        const lv = window.localStorage.getItem(key);
        if (lv != null) out.push({ key, value: lv, store: "local" });
        const sv = window.sessionStorage.getItem(key);
        if (sv != null) out.push({ key, value: sv, store: "session" });
      }
      return out;
    },
  });
  return result || [];
}

/* ------------------------------------------------- switch user (safe) ---- */

async function switchUser(url, tabId) {
  if (!url || !/^https?:/i.test(url)) throw new Error("Open the target page first.");
  const origin = new URL(url).origin;
  const cleared = [];

  // 1. remove cookies for the origin locally (NO /logout call - keeps the
  //    captured server-side session alive). Use each cookie's own path so
  //    non-root-path cookies actually match and get removed.
  const cookies = await chrome.cookies.getAll({ url });
  for (const c of cookies) {
    const scheme = c.secure ? "https" : "http";
    const host = c.domain.replace(/^\./, "");
    await chrome.cookies
      .remove({ url: `${scheme}://${host}${c.path || "/"}`, name: c.name })
      .catch(() => {});
  }
  if (cookies.length) cleared.push(`${cookies.length} cookie${cookies.length > 1 ? "s" : ""}`);

  // 2. clear ALL origin-keyed storage - many apps keep the session token in
  //    IndexedDB (Firebase Auth, OAuth libs) or restore it from a service
  //    worker, not just cookies/localStorage. This is why clearing only
  //    cookies often leaves you logged in.
  if (chrome.browsingData?.remove) {
    await chrome.browsingData
      .remove(
        { origins: [origin] },
        {
          cookies: true,
          localStorage: true,
          indexedDB: true,
          serviceWorkers: true,
          cacheStorage: true,
          webSQL: true,
          fileSystems: true,
        }
      )
      .then(() => cleared.push("localStorage", "IndexedDB", "service workers", "cache"))
      .catch(() => {});
  }

  // 3. sessionStorage is tab-scoped (browsingData can't target it) - clear it in
  //    the page, then reload so the app shows logged-out / a fresh login page.
  if (tabId != null) {
    await chrome.scripting
      .executeScript({
        target: { tabId },
        func: () => {
          try {
            window.sessionStorage.clear();
            window.localStorage.clear();
          } catch {
            /* ignore */
          }
        },
      })
      .catch(() => {});
    await chrome.tabs.reload(tabId).catch(() => {});
  }

  return { ...state(), switchedOrigin: origin, removedCookies: cookies.length, cleared };
}
