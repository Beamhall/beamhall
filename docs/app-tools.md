# App tools — let users' agents call your app

Any beam can expose **tools** to the agents of the people it's published to:
Erik asks his own AI assistant to "file three days of leave", the assistant
finds the HR app with `list_apps`, and calls the app's `request_time_off` tool
through Beamhall — no browser, no separate sign-in, no API key. This document
is the reference for the app side of that contract.

The moving parts:

- **Your app serves two routes** (any language, any framework — it's plain
  HTTP on your app's own origin).
- **Beamhall brokers every call.** A user's agent calls the Beamhall tool
  `use_app`; the backplane relays it to your app's live workload. Builders test
  the same surface pre-production with `try_beam_tool` against the preview
  channel. Agents never reach your app's tool routes directly through Beamhall,
  and your app never sees anyone's IdP token.
- **Beamhall tells you who is calling** with a signed assertion your app
  verifies using material Beamhall mounts into every workload.

Nothing has to be enabled: serve the contract and it works. Who can *call* is
governed the same way as who can *see* the app — IT promotes it to production
(`promote_to_live`) and publishes it to an audience (`admin_set_app_audience`);
until then only your team's builders can reach the tools, on the preview
channel.

## The contract (version 1)

### 1. The menu — `GET /.beamhall/tools`

Return `200` with `Content-Type: application/json`:

```json
{
  "version": 1,
  "tools": [
    {
      "name": "request_time_off",
      "description": "File a leave request for the calling employee",
      "input_schema": {
        "type": "object",
        "properties": {
          "from": { "type": "string", "format": "date" },
          "days": { "type": "number" }
        },
        "required": ["from", "days"]
      }
    }
  ]
}
```

- `name`: `^[a-z0-9][a-z0-9_-]{0,63}$`, unique within the menu.
- `description`: written for the calling agent — say what the tool does and
  when to use it.
- `input_schema`: optional JSON Schema object for the arguments.
- An **empty `tools` array is a valid menu**. The menu may differ per caller —
  the assertion rides the menu request too, so you can tailor what you offer.

### 2. The invocation — `POST /.beamhall/tools/<name>`

The body is the JSON arguments object. Answer `2xx` with a JSON body (your
answer is relayed to the agent verbatim); answer any other status with a short
explanation (relayed as the tool's failure).

### Limits Beamhall enforces

| What | Limit |
|---|---|
| Menu response | 64 KiB, ≤ 64 tools |
| Arguments | 64 KiB |
| Result body | 256 KiB (larger answers are refused — paginate) |
| Invocation time | 30 s by default (`BEAMHALL_APP_TOOL_TIMEOUT_SECS`) |
| Menu fetch time | 5 s |

Relayed menus and results pass Beamhall's secret scrubber before they reach
the agent, and every brokered call lands on the appliance's audit chain under
the caller's identity.

## Verifying the caller — REQUIRED

Every brokered request carries the header:

```
Beamhall-Assertion: <ES256 JWS>
```

Its claims:

| Claim | Meaning |
|---|---|
| `iss` | the appliance (must equal `issuer` from the mounted file) |
| `aud` | your beam's ID (must equal `audience` from the mounted file) |
| `sub` | the caller's Beamhall identity ID; for `caller_type: "beam"` the calling beam's ID; `beamhall:probe` for the capability probe |
| `caller_type` | `user` (a person's agent), `beam` (another app, via an IT grant — see "Calling other apps"), or `probe` |
| `email` | the caller's email (empty for beams and the probe) |
| `groups` | the caller's IdP group names (always an array; empty for beams) |
| `channel` | `live` or `preview` — which of your channels is being called |
| `tool` | the tool named in the URL (`""` for a menu fetch) |
| `jti`, `iat`, `exp` | one-time ID and a ~60-second validity window |

If your app authorizes on identity, **branch on `caller_type`**: a beam caller
has no email or groups, and treating it as an anonymous user could fail open
or closed in ways you didn't design. Assertions minted before this claim
existed do not occur — every current appliance stamps it.

Every deploy mounts the verification material at
**`/run/beamhall/assertion.json`**:

```json
{ "version": 1,
  "issuer": "https://beamhall.example.com/mcp",
  "audience": "<your-beam-id>",
  "jwks": { "keys": [ { "kty": "EC", "crv": "P-256", "kid": "…", "x": "…", "y": "…" } ] } }
```

**Your app MUST verify the assertion on BOTH routes and answer `401` without
a valid one.** The tool routes live on your app's public URL — an app that
skips verification hands its tools to anyone who finds the URL, with whatever
identity they claim. Check, at minimum: the ES256 signature against the
mounted JWKS, `iss` == `issuer`, `aud` == `audience`, `exp`, and that `tool`
matches the route being called.

Use `sub` (stable) or `email` for per-user data, and `groups`/`channel` for
your own authorization — the assertion is how "the HR app answers only about
*your* leave balance" works.

### Node (no dependencies)

```js
const crypto = require("crypto");
const conf = JSON.parse(require("fs").readFileSync("/run/beamhall/assertion.json", "utf8"));
const key = crypto.createPublicKey({ key: conf.jwks.keys[0], format: "jwk" });

function verifyAssertion(req, wantTool) {
  const tok = req.headers["beamhall-assertion"];
  if (!tok) return null;
  const [h, p, s] = tok.split(".");
  if (!s) return null;
  const ok = crypto.verify("sha256", Buffer.from(h + "." + p),
    { key, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"));
  if (!ok) return null;
  const c = JSON.parse(Buffer.from(p, "base64url").toString());
  if (c.iss !== conf.issuer || c.aud !== conf.audience) return null;
  if (!c.exp || c.exp < Date.now() / 1000) return null;
  if ((c.tool || "") !== wantTool) return null;
  return c; // { sub, email, groups, channel, ... }
}
```

### Python

```python
import json, jwt  # PyJWT
from jwt import PyJWK

conf = json.load(open("/run/beamhall/assertion.json"))
key = PyJWK.from_dict(conf["jwks"]["keys"][0]).key

def verify_assertion(headers, want_tool):
    tok = headers.get("Beamhall-Assertion")
    if not tok:
        return None
    try:
        c = jwt.decode(tok, key, algorithms=["ES256"],
                       issuer=conf["issuer"], audience=conf["audience"])
    except jwt.PyJWTError:
        return None
    return c if c.get("tool", "") == want_tool else None
```

## The lifecycle

1. **Build**: serve the two routes; verify the assertion.
2. **Test**: `try_beam_tool` (builder) exercises them on the preview channel —
   the assertion arrives with `channel: "preview"` and the builder's identity.
3. **Ship**: `promote_to_live` (IT approval). At each workload start Beamhall
   probes the menu once; a live app that answers it shows
   `agent_tools: true` in `describe_app` (advisory — `use_app` always fetches
   the real menu).
4. **Publish**: IT runs `admin_set_app_audience`. From then on, the audience's
   agents discover the app with `list_apps` and call it with `use_app`.
   Unpublishing removes it from discovery and from `use_app` immediately.

## Calling other apps (beam-to-beam)

Apps cannot reach each other over the network — sibling and cross-workspace
traffic is closed at the bridge. The only path is the **Beamhall relay**, and
only for targets IT has granted your app with `admin_set_beam_peers`
(builders see the current grant with `show_beam_peers`).

After the first grant, your workload's **next deploy** mounts:

- **`/run/beamhall/c2c.json`** — `{ "version": 1, "endpoint": "http://<gateway-ip>:<port>", "key_file": "/run/secrets/BEAMHALL_C2C_KEY" }`
- the relay key at that `key_file` path.

Send the key's contents in the **`Beamhall-C2C-Key`** header to:

| Route | Meaning |
|---|---|
| `GET  <endpoint>/c2c/v1/peers` | the apps you may reach, live-fresh: `{"version":1,"peers":[{"workspace":…,"app":…,"live":…,"agent_tools":…}]}` |
| `GET  <endpoint>/c2c/v1/peer/<workspace>/<app>/tools` | that app's tool menu (this contract's manifest shape) |
| `POST <endpoint>/c2c/v1/peer/<workspace>/<app>/tools/<name>` | invoke one tool, JSON arguments in the body |

Rules and behavior:

- Targets are called on their **live channel only** and must serve this
  contract; they see your call as a verified assertion with
  `caller_type: "beam"` and `sub` = your beam's ID.
- The relay re-checks the grant on **every call** (revocation is instant),
  verifies the calling workload by its key **and** its container address (a
  copied key does not work from anywhere else), applies the same size caps as
  `use_app`, rate-limits per beam, and records **every call on the audit
  chain**.
- Errors are teaching JSON (`{"error":…,"hint":…}`). An app outside your
  grant answers exactly like one that does not exist.
- The file and key ride deploys: a rollback to a release from before the
  grant carries neither — treat `c2c.json`'s absence as "no peers granted".

## Notes

- Users reach only the **live** channel; there is no brokered path from a
  user to your preview.
- The verification file is (re)mounted at **each deploy**. If the appliance's
  assertion key ever changes (a restore from before the key existed), redeploy
  to pick up the new JWKS.
- The capability probe calls the menu with `sub: "beamhall:probe"` right after
  your workload starts — treat it as any other menu fetch.
