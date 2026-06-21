// Beamhall canonical demo — "Request Tracker", a tiny internal tool.
//
// It demonstrates the whole value proposition from inside a beam:
//   * a write-only secret arrives as a FILE at /run/secrets/API_TOKEN — the
//     agent that deployed this never saw the value;
//   * a managed Postgres database arrives as a DSN at /run/secrets/MAIN_URL —
//     again a file, never the connection string in code or env;
//   * no Dockerfile: Beamhall's buildpacks detect Node from package.json.
//
// It logs the token at boot ON PURPOSE so the demo can show that show_logs
// scrubs secrets before the agent ever sees them.
"use strict";

const http = require("http");
const fs = require("fs");

const PORT = process.env.PORT || 8080;
const RELEASE = readFileSync("./VERSION", "v1"); // bumped by the demo driver for the rollback story

// --- secret + resource injection (files, never env/raw creds) ---------------
const apiToken = readFileSync("/run/secrets/API_TOKEN", "");
const dbUrl = readFileSync("/run/secrets/MAIN_URL", "");

// Deliberate: prove the scrubber has a real leak to catch in show_logs.
console.log(`booted release=${RELEASE}; api token is ${apiToken || "(none)"}`);

// --- managed database (graceful: the page still serves if the DB is slow) ---
let db = null;
let dbState = dbUrl ? "connecting" : "not provisioned";
if (dbUrl) {
  try {
    const { Pool } = require("pg");
    db = new Pool({ connectionString: dbUrl.trim(), max: 2 });
    db.query(
      "CREATE TABLE IF NOT EXISTS visits (id BIGSERIAL PRIMARY KEY, at TIMESTAMPTZ NOT NULL DEFAULT now())"
    )
      .then(() => { dbState = "ready"; })
      .catch((e) => { dbState = "error: " + e.code; });
  } catch (e) {
    dbState = "driver error: " + e.message;
  }
}

async function recordVisit() {
  if (!db || dbState !== "ready") return null;
  try {
    await db.query("INSERT INTO visits DEFAULT VALUES");
    const r = await db.query("SELECT count(*)::int AS n FROM visits");
    return r.rows[0].n;
  } catch (e) {
    dbState = "error: " + e.code;
    return null;
  }
}

// --- HTTP -------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  if (req.url === "/healthz") {
    res.writeHead(200, { "content-type": "text/plain" });
    return res.end("ok");
  }
  if (req.url === "/api/status") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({
      release: RELEASE,
      host: require("os").hostname(),
      hasToken: apiToken.length > 0,
      database: dbState,
    }));
  }

  const visits = await recordVisit();
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(page({ visits }));
});
server.listen(PORT, () => console.log(`tracker listening on :${PORT}`));

for (const sig of ["SIGTERM", "SIGINT"]) {
  process.on(sig, () => server.close(() => process.exit(0)));
}

// --- helpers ----------------------------------------------------------------
function readFileSync(path, fallback) {
  try { return fs.readFileSync(path, "utf8"); } catch { return fallback; }
}

function page({ visits }) {
  const badge = (ok, on, off) =>
    `<span class="badge ${ok ? "ok" : "off"}">${ok ? on : off}</span>`;
  return `<!doctype html><html><head><meta charset="utf-8">
<title>Beamhall demo — Request Tracker</title>
<style>
  body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:6vh auto;padding:0 1rem;color:#111}
  h1{font-size:1.6rem;margin-bottom:.2rem}.rel{color:#6b46c1;font-weight:600}
  .card{border:1px solid #e5e7eb;border-radius:12px;padding:1rem 1.25rem;margin:1rem 0}
  .row{display:flex;justify-content:space-between;padding:.35rem 0;border-bottom:1px solid #f3f4f6}
  .row:last-child{border:0}.badge{font-size:.8rem;padding:.1rem .5rem;border-radius:999px}
  .ok{background:#dcfce7;color:#166534}.off{background:#fee2e2;color:#991b1b}
  .big{font-size:2.4rem;font-weight:700}
</style></head><body>
  <h1>Request Tracker <span class="rel">${RELEASE}</span></h1>
  <div>An internal beam deployed by an AI agent — with no credentials in the agent's hands.</div>
  <div class="card">
    <div class="row"><span>API token (write-only secret)</span>${badge(apiToken.length > 0, "injected ✓", "missing")}</div>
    <div class="row"><span>Managed database</span>${badge(dbState === "ready", dbState, dbState)}</div>
    <div class="row"><span>Host</span><code>${require("os").hostname()}</code></div>
  </div>
  <div class="card" style="text-align:center">
    <div>tracked requests</div>
    <div class="big">${visits == null ? "—" : visits}</div>
  </div>
</body></html>`;
}
