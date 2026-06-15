/**
 * Identity model + persistence (shared by the background worker and panel).
 *
 * An Identity is a captured authentication context for one user on one target:
 *   - cookies:      [{ name, value, domain, path }]   (incl. HttpOnly session cookies)
 *   - authHeaders:  { Authorization: "Bearer ...", "X-Api-Key": "..." }
 *   - tokenStorage: [{ key, value, store: "local" | "session" }]  (JWTs in web storage)
 *
 * When a request is replayed as this identity, its cookies / auth headers are
 * swapped in (see the replay engine). The unauthenticated lane is NOT an
 * identity - it is a fixed lane that strips all credentials.
 */

const STORAGE_KEY = "azr.identities";

const PALETTE = ["#4f9cf4", "#e0a458", "#9b8afb", "#3fb950", "#f06c75", "#56b6c2"];

export function makeId() {
  return `id_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`;
}

export function emptyIdentity() {
  return {
    id: makeId(),
    label: "",
    color: PALETTE[Math.floor(Math.random() * PALETTE.length)],
    scopeDomain: "",
    cookies: [],
    authHeaders: {},
    tokenStorage: [],
    capturedAt: null,
  };
}

/** Build an Identity from a live capture (cookies + observed headers + storage). */
export function identityFromCapture({ label, origin, cookies, authHeaders, tokenStorage, index }) {
  return {
    id: makeId(),
    label: label || `User ${String.fromCharCode(64 + (index || 1))}`, // A, B, C…
    color: PALETTE[((index || 1) - 1) % PALETTE.length],
    scopeDomain: origin || "",
    cookies: cookies || [],
    authHeaders: authHeaders || {},
    tokenStorage: tokenStorage || [],
    capturedAt: Date.now(),
  };
}

/** A single `Cookie:` header value built from the identity's cookie jar. */
export function cookieHeader(identity) {
  return (identity.cookies || []).map((c) => `${c.name}=${c.value}`).join("; ");
}

export function hasCredentials(identity) {
  if (!identity) return false;
  return !!(
    (identity.cookies || []).length ||
    Object.keys(identity.authHeaders || {}).length ||
    (identity.tokenStorage || []).length
  );
}

export function summarize(identity) {
  const parts = [];
  const cc = (identity.cookies || []).length;
  if (cc) parts.push(`${cc} cookie${cc > 1 ? "s" : ""}`);
  const ah = Object.keys(identity.authHeaders || {});
  if (ah.length) parts.push(ah.join(" + "));
  const ts = (identity.tokenStorage || []).length;
  if (ts) parts.push(`${ts} token${ts > 1 ? "s" : ""}`);
  return parts.length ? parts.join(" · ") : "no credentials";
}

export async function loadIdentities() {
  const data = await chrome.storage.local.get(STORAGE_KEY);
  const list = data[STORAGE_KEY];
  if (!Array.isArray(list)) return [];
  let mutated = false;
  const upgraded = list
    .map((it) => {
      const m = migrate(it);
      if (m !== it) mutated = true;
      return m;
    })
    .filter(Boolean);
  if (mutated) await saveIdentities(upgraded);
  return upgraded;
}

export async function saveIdentities(list) {
  await chrome.storage.local.set({ [STORAGE_KEY]: list });
}

/** Upgrade a pre-0.4 identity (cookie string + headers array + stripAuth) in place. */
function migrate(it) {
  if (!it || typeof it !== "object") return null;
  if (it.cookies && it.authHeaders) return it; // already new shape
  // legacy "No-auth" pseudo-identity is now the fixed unauth lane - drop it.
  if (it.stripAuth) return null;

  const cookies = parseCookieString(it.cookie || "", it.origin || "");
  const authHeaders = {};
  for (const h of it.headers || []) {
    if (h && h.name) authHeaders[h.name] = h.value;
  }
  return {
    id: it.id || makeId(),
    label: it.name || it.label || "User",
    color: it.color || PALETTE[0],
    scopeDomain: it.origin || it.scopeDomain || "",
    cookies,
    authHeaders,
    tokenStorage: it.tokenStorage || [],
    capturedAt: it.capturedAt || null,
  };
}

function parseCookieString(str, origin) {
  const host = hostOf(origin);
  return String(str || "")
    .split(";")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const eq = p.indexOf("=");
      const name = eq === -1 ? p : p.slice(0, eq);
      const value = eq === -1 ? "" : p.slice(eq + 1);
      return { name, value, domain: host, path: "/" };
    });
}

export function hostOf(origin) {
  try {
    return new URL(origin).host;
  } catch {
    return origin || "";
  }
}
