/**
 * Scope control. The extension only intercepts / replays requests whose URL
 * matches an include pattern and no exclude pattern. Default scope is empty, so
 * nothing is touched until the user (or a capture) adds a target.
 *
 * Patterns are simple globs over the full URL, e.g.
 *   https://app.example.com/*
 *   https://*.example.com/api/*
 * `*` matches any run of characters; everything else is literal.
 */

export function globToRegExp(glob) {
  const escaped = String(glob)
    .trim()
    .replace(/[.+^${}()|[\]\\]/g, "\\$&") // escape regex metachars (keep * and ?)
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}

export function matchesAny(url, patterns) {
  for (const p of patterns || []) {
    const pat = String(p || "").trim();
    if (!pat) continue;
    try {
      if (globToRegExp(pat).test(url)) return true;
    } catch {
      /* skip bad pattern */
    }
  }
  return false;
}

export function inScope(url, config) {
  if (!config || !Array.isArray(config.includeScopes) || config.includeScopes.length === 0) {
    return false;
  }
  if (!matchesAny(url, config.includeScopes)) return false;
  if (matchesAny(url, config.excludeScopes)) return false;
  return true;
}

/** A sensible include pattern covering a whole origin, e.g. https://app.example.com/* */
export function originPattern(url) {
  try {
    return `${new URL(url).origin}/*`;
  } catch {
    return "";
  }
}
