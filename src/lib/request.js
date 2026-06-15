/**
 * Request shape analysis - mainly so we don't treat GraphQL (and similar
 * RPC-over-POST) *reads* as state-changing writes.
 *
 * A GraphQL query is a read sent as a POST. The naive "any POST/PUT/PATCH/DELETE
 * mutates state" rule would (a) refuse to auto-replay it and (b) flag a 2xx as
 * BYPASSED on method alone. Here we look at the body: only a `mutation` counts
 * as a write; a `query`/`subscription` is a read.
 */

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Pull the GraphQL query string(s) out of a request body, or null if not GraphQL-shaped. */
function graphqlQueries(body) {
  if (!body) return null;
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  const queries = [];
  for (const item of items) {
    if (item && typeof item === "object" && typeof item.query === "string") {
      queries.push(item.query);
    }
  }
  return queries.length ? queries : null;
}

export function isGraphqlRequest({ url, body }) {
  try {
    if (/\/graphql\b|\/gql\b/i.test(new URL(url).pathname)) return true;
  } catch {
    /* ignore */
  }
  return graphqlQueries(body) !== null;
}

/** True if the GraphQL body contains at least one `mutation` operation. */
export function graphqlIsMutation(body) {
  const queries = graphqlQueries(body);
  if (!queries) return false;
  for (const q of queries) {
    // strip string literals and comments so a field literally named "mutation"
    // inside a string can't trip the keyword match
    const stripped = q.replace(/"(?:\\.|[^"\\])*"/g, "").replace(/#[^\n]*/g, "");
    if (/(^|[\s{};])mutation\b/i.test(stripped)) return true;
  }
  return false;
}

/**
 * Classify a request as a read or a state-changing write.
 * @returns {{ kind: "rest"|"graphql", isWrite: boolean }}
 */
export function analyzeRequest({ method, url, body }) {
  const m = (method || "GET").toUpperCase();
  if (isGraphqlRequest({ url, body })) {
    return { kind: "graphql", isWrite: graphqlIsMutation(body) };
  }
  return { kind: "rest", isWrite: WRITE_METHODS.has(m) };
}

/**
 * Inspect a GraphQL *response* body (which is almost always HTTP 200, even on
 * failure - errors live in the body).
 * @returns {"ok"|"error"|null} "ok" = data returned, "error" = errors / no data,
 *          null = not GraphQL-shaped (fall back to normal comparison).
 */
export function graphqlResponseStatus(body) {
  if (!body) return null;
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  let sawShape = false;
  let sawError = false;
  let sawData = false;
  for (const it of items) {
    if (!it || typeof it !== "object") continue;
    if ("errors" in it || "data" in it) sawShape = true;
    if (Array.isArray(it.errors) && it.errors.length) sawError = true;
    if ("data" in it && it.data != null) {
      const empty = typeof it.data === "object" && Object.keys(it.data).length === 0;
      if (!empty) sawData = true;
    }
  }
  if (!sawShape) return null;
  if (sawError) return "error";
  return sawData ? "ok" : "error";
}
