/**
 * Enforcement classification.
 *
 * Design rule (from the spec): do NOT classify on status code alone - it
 * produces massive false positives (e.g. a "current user" endpoint returns 200
 * for everyone with *their own* data; some apps return 200 with an error body
 * instead of 403).
 *
 * For each replay lane we compare its response to the ORIGINAL response
 * (the browsing identity's own request, re-issued so we have a body to diff)
 * and apply, in order:
 *
 *   1. status short-circuits  - 401/403/407, redirects, 404/405/410 = ENFORCED.
 *   2. owner-marker hit        - replay body contains A's tagged email/id = BYPASSED.
 *   3. auth-wall body          - 2xx whose body is a login/error page    = ENFORCED.
 *   4. graphql result          - 2xx GraphQL with errors = ENFORCED; a mutation
 *                                that returned data = BYPASSED; a query falls
 *                                through to the body comparison below.
 *   5. write-method success    - 2xx on a state-changing REST request     = BYPASSED.
 *   6. baseline guard          - no good A baseline, or A is itself an
 *                                auth-wall (expired creds)               = UNCLEAR.
 *   7. empty-body              - replay empty while A had data            = ENFORCED.
 *   8. body similarity         - JSON-structural or token Jaccard:
 *                                  high  = BYPASSED
 *                                  low   = ENFORCED
 *                                  mid   = UNCLEAR
 */

import { graphqlResponseStatus } from "./request.js";

export const DEFAULT_VOLATILE_PATTERNS = [
  // ISO-8601 timestamps
  "\\d{4}-\\d{2}-\\d{2}T[0-9:.,+Z\\-]+",
  // common volatile JSON fields (string values)
  '"(?:created_at|updated_at|modified_at|timestamp|time|date|last_seen|expires_at|nonce|csrf|csrf_token|_token|xsrf|request_id|requestId|trace_id|traceId|span_id|etag|session_id)"\\s*:\\s*"[^"]*"',
  // common volatile JSON fields (numeric values)
  '"(?:created_at|updated_at|timestamp|time|expires_at|exp|iat|ts)"\\s*:\\s*\\d+',
  // hex/uuid request ids in headers-ish text
  "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
];

// JSON keys whose values are volatile and should not count toward structural
// similarity (used by the JSON-aware comparison path).
const VOLATILE_KEYS = new Set([
  "created_at", "updated_at", "modified_at", "timestamp", "time", "date",
  "last_seen", "expires_at", "exp", "iat", "ts", "nonce", "csrf", "csrf_token",
  "_token", "xsrf", "request_id", "requestid", "trace_id", "traceid", "span_id",
  "etag", "session_id",
]);

// Phrases that mean "you are not allowed / not logged in", even on a 2xx.
const AUTHWALL_RE =
  /(unauthori[sz]ed|forbidden|access[ _-]?denied|permission[ _-]?denied|not[ _-]?allowed|must (?:be )?log[ _-]?in|please (?:log|sign)[ _-]?in|log[ _-]?in to continue|authentication required|invalid (?:token|session|credentials)|session (?:expired|invalid)|not authenticated|login required)/i;

// HTML login form fingerprints.
const LOGINFORM_RE =
  /(<form[^>]*(?:login|signin|sign-in|auth)|type=["']password["']|name=["']password["'])/i;

export function normalizeBody(body, patterns) {
  let text = String(body || "");
  for (const p of patterns || []) {
    if (!p) continue;
    try {
      text = text.replace(new RegExp(p, "gi"), "");
    } catch {
      /* ignore invalid pattern */
    }
  }
  return text.replace(/\s+/g, " ").trim();
}

/** Token Jaccard similarity in [0,1], blended with a length ratio. */
export function similarity(a, b) {
  if (!a && !b) return 1;
  if (!a || !b) return 0;
  const ta = tokenize(a);
  const tb = tokenize(b);
  if (ta.size === 0 && tb.size === 0) return 1;
  let inter = 0;
  for (const t of ta) if (tb.has(t)) inter++;
  const union = ta.size + tb.size - inter;
  const jaccard = union === 0 ? 1 : inter / union;
  const lenRatio = Math.min(a.length, b.length) / Math.max(a.length, b.length || 1);
  return 0.7 * jaccard + 0.3 * lenRatio;
}

function tokenize(text) {
  return new Set(text.toLowerCase().split(/[^a-z0-9_]+/).filter((t) => t.length > 1));
}

/** Flatten JSON into a set of `path=value` leaf strings, dropping volatile keys. */
function jsonLeaves(value, prefix, out) {
  if (value === null || typeof value !== "object") {
    out.add(`${prefix}=${value}`);
    return out;
  }
  if (Array.isArray(value)) {
    // Array order can be unstable; index leaves by content, not position.
    for (const item of value) jsonLeaves(item, `${prefix}[]`, out);
    return out;
  }
  for (const key of Object.keys(value)) {
    if (VOLATILE_KEYS.has(key.toLowerCase())) continue;
    jsonLeaves(value[key], prefix ? `${prefix}.${key}` : key, out);
  }
  return out;
}

/**
 * JSON-aware structural similarity. Returns a number in [0,1] when BOTH inputs
 * parse as JSON, else null so the caller can fall back to token similarity.
 */
export function jsonSimilarity(rawA, rawB) {
  let a, b;
  try {
    a = JSON.parse(String(rawA || "").trim());
    b = JSON.parse(String(rawB || "").trim());
  } catch {
    return null;
  }
  const la = jsonLeaves(a, "", new Set());
  const lb = jsonLeaves(b, "", new Set());
  if (la.size === 0 && lb.size === 0) return 1;
  let inter = 0;
  for (const leaf of la) if (lb.has(leaf)) inter++;
  const union = la.size + lb.size - inter;
  return union === 0 ? 1 : inter / union;
}

/** Best available body similarity: structural for JSON, token-based otherwise. */
function bodySimilarity(rawA, rawB, patterns) {
  const j = jsonSimilarity(rawA, rawB);
  if (j !== null) return j;
  return similarity(normalizeBody(rawA, patterns), normalizeBody(rawB, patterns));
}

function isEmptyBody(text) {
  return String(text || "").trim() === "";
}

/** Does a 2xx body actually mean "denied / log in" rather than real data? */
export function looksLikeAuthWall(body) {
  const text = String(body || "");
  if (!text.trim()) return false;
  return AUTHWALL_RE.test(text) || LOGINFORM_RE.test(text);
}

/** First owner marker (A's email/id/etc.) found verbatim in the replay body. */
function markerHit(body, markers) {
  if (!markers || !body) return null;
  const text = String(body);
  const low = text.toLowerCase();
  for (const m of markers) {
    const needle = String(m || "").trim();
    if (needle.length < 3) continue;
    if (low.includes(needle.toLowerCase())) return needle;
  }
  return null;
}

const HIGH = 0.85;
const LOW = 0.4;
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * @param {{original:object|null, lane:object, isUnauth?:boolean, patterns?:string[], method?:string, markers?:string[], isWrite?:boolean, kind?:string}} args
 * @returns {{verdict:"BYPASSED"|"ENFORCED"|"UNCLEAR", reason:string, similarity:number|null}}
 */
export function classify({ original, lane, isUnauth, patterns, method, markers, isWrite, kind }) {
  if (!lane || lane.error) {
    return { verdict: "UNCLEAR", reason: lane?.error ? `Replay failed: ${lane.error}` : "No replay result.", similarity: null };
  }
  const s = lane.status;
  const who = isUnauth ? "Unauthenticated" : "Replay identity";
  const sev = isUnauth ? " (unauthenticated access - highest severity)" : "";
  const write = isWrite !== undefined ? isWrite : WRITE_METHODS.has((method || "").toUpperCase());
  const isGraphql = kind === "graphql";

  // 1. Status short-circuits.
  if ([401, 403, 407].includes(s)) {
    return { verdict: "ENFORCED", reason: `${who} rejected with ${s}.`, similarity: null };
  }
  if (s >= 300 && s < 400) {
    return { verdict: "ENFORCED", reason: `${who} redirected (${s}) - likely bounced to login.`, similarity: null };
  }
  if ([404, 405, 410].includes(s)) {
    return { verdict: "ENFORCED", reason: `${who} got ${s} - object hidden/blocked for this identity (or state already changed).`, similarity: null };
  }
  if (!s) {
    return { verdict: "UNCLEAR", reason: `${who} request failed (network / CORS).`, similarity: null };
  }
  if (!(s >= 200 && s < 300)) {
    return { verdict: "UNCLEAR", reason: `${who} returned ${s}.`, similarity: null };
  }

  // ---- 2xx from here on ----

  // 2. Owner-marker hit: A's tagged identifier showed up in this identity's
  //    response. Strongest possible signal - they read the owner's data.
  const hit = markerHit(lane.body, markers);
  if (hit) {
    return { verdict: "BYPASSED", reason: `${who} got ${s} and its body contains the owner marker "${truncate(hit)}"${sev}.`, similarity: null };
  }

  // 3. Auth-wall body: 2xx that is really a login/error page.
  if (looksLikeAuthWall(lane.body)) {
    return { verdict: "ENFORCED", reason: `${who} got ${s} but the body is a login/error page, not the resource.`, similarity: null };
  }

  // 4. GraphQL (and similar) return 200 even on failure - the verdict is in the
  //    body. Errors mean the operation was refused; data on a mutation means it
  //    ran. A query with data falls through to the body comparison below.
  if (isGraphql) {
    const g = graphqlResponseStatus(lane.body);
    if (g === "error") {
      return { verdict: "ENFORCED", reason: `${who} got ${s} but the GraphQL response returned errors (operation refused).`, similarity: null };
    }
    if (g === "ok" && write) {
      return { verdict: "BYPASSED", reason: `${who} got ${s} and the GraphQL mutation returned data - the action was accepted${sev}.`, similarity: null };
    }
  } else if (write) {
    // 5. Write-method success: the state-changing action was accepted as this
    //    identity. Body similarity is irrelevant - the side effect happened.
    return { verdict: "BYPASSED", reason: `${who} got ${s} on a ${(method || "").toUpperCase()} - the state-changing action was accepted${sev}.`, similarity: null };
  }

  // 6. Baseline guard: we can only diff reads against a trustworthy owner body.
  if (!original || !(original.status >= 200 && original.status < 300)) {
    return { verdict: "UNCLEAR", reason: `${who} returned ${s}, but there is no successful baseline to compare against.`, similarity: null };
  }
  if (looksLikeAuthWall(original.body)) {
    return { verdict: "UNCLEAR", reason: `${who} returned ${s}, but the owner's baseline looks like a login/error page (A's session may have expired) - recapture and retry.`, similarity: null };
  }

  // 7. Empty-body handling.
  const laneEmpty = isEmptyBody(lane.body) || s === 204;
  const origEmpty = isEmptyBody(original.body);
  if (laneEmpty && !origEmpty) {
    return { verdict: "ENFORCED", reason: `${who} got ${s} with an empty body while the owner received data - looks like nothing was returned.`, similarity: 0 };
  }
  if (laneEmpty && origEmpty) {
    return { verdict: "UNCLEAR", reason: `${who} and the owner both returned empty bodies - cannot tell them apart.`, similarity: null };
  }

  // 8. Body similarity (JSON-structural when possible).
  const sim = bodySimilarity(original.body, lane.body, patterns);
  if (sim >= HIGH) {
    return { verdict: "BYPASSED", reason: `${who} got ${s} with a response ${pct(sim)} similar to the owner's${sev}.`, similarity: sim };
  }
  if (sim < LOW) {
    return { verdict: "ENFORCED", reason: `${who} got ${s} but the response is only ${pct(sim)} similar - looks like its own/empty data.`, similarity: sim };
  }
  return { verdict: "UNCLEAR", reason: `${who} got ${s} with ${pct(sim)} body similarity - review manually.`, similarity: sim };
}

function pct(x) {
  return `${Math.round(x * 100)}%`;
}

function truncate(text, n = 40) {
  const t = String(text);
  return t.length > n ? `${t.slice(0, n)}...` : t;
}

export const VERDICT_RANK = { BYPASSED: 4, UNCLEAR: 3, PENDING: 2, ENFORCED: 1 };

export function worstVerdict(list) {
  let best = null;
  let rank = -1;
  for (const v of list) {
    if (!v) continue;
    const r = VERDICT_RANK[v] ?? -1;
    if (r > rank) {
      rank = r;
      best = v;
    }
  }
  return best || "PENDING";
}

/** Pretty-print a response/request body for display, capped so the panel stays light. */
export function prettyBody(text, cap = 8000) {
  if (!text) return "";
  const trimmed = String(text).trim();
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2).slice(0, cap);
  } catch {
    return trimmed.slice(0, cap);
  }
}
