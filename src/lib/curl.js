/**
 * Reproduce a lane's exact request as a copy-pasteable command.
 * `headers` is a plain object of the headers actually sent for that lane
 * (including the swapped Cookie / Authorization), so the command reproduces
 * the request as that identity.
 */

export function toCurl({ method, url, headers, body }) {
  const lines = [`curl -i -X ${shellMethod(method)} ${q(url)}`];
  for (const [name, value] of Object.entries(headers || {})) {
    lines.push(`  -H ${q(`${name}: ${value}`)}`);
  }
  if (body && !["GET", "HEAD"].includes((method || "").toUpperCase())) {
    lines.push(`  --data-raw ${q(body)}`);
  }
  return lines.join(" \\\n");
}

export function toFetch({ method, url, headers, body }) {
  const init = { method: (method || "GET").toUpperCase(), headers: headers || {} };
  if (body && !["GET", "HEAD"].includes(init.method)) init.body = body;
  return `fetch(${JSON.stringify(url)}, ${JSON.stringify(init, null, 2)});`;
}

function shellMethod(m) {
  return (m || "GET").toUpperCase().replace(/[^A-Z]/g, "");
}

// single-quote for POSIX shells, escaping embedded single quotes
function q(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}
