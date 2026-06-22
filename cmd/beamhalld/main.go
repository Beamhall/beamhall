// Command beamhalld is the single-binary Beamhall appliance: the backplane
// (store, vault, audit chain, PEP, orchestrator), the build pipeline, and the
// agent-facing remote MCP server in one process supervised by systemd.
package main

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/auth"
	"github.com/Beamhall/beamhall/internal/backup"
	"github.com/Beamhall/beamhall/internal/build"
	"github.com/Beamhall/beamhall/internal/config"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/egress"
	"github.com/Beamhall/beamhall/internal/gateway"
	"github.com/Beamhall/beamhall/internal/gitserver"
	"github.com/Beamhall/beamhall/internal/identityadmin"
	"github.com/Beamhall/beamhall/internal/mcp"
	"github.com/Beamhall/beamhall/internal/orch"
	"github.com/Beamhall/beamhall/internal/policy"
	"github.com/Beamhall/beamhall/internal/resource"
	"github.com/Beamhall/beamhall/internal/scheduler"
	"github.com/Beamhall/beamhall/internal/secret"
	"github.com/Beamhall/beamhall/internal/store"
	"github.com/Beamhall/beamhall/internal/web"
)

// gitDeployer adapts the orchestrator to the git server's deploy callback: it
// builds+deploys the pushed commit as the token's actor (re-checked by the
// PEP), streams build progress to the push client, and returns the beam's
// active URL.
func gitDeployer(o *orch.Orchestrator, st *store.Store, logger *slog.Logger) gitserver.Deployer {
	return func(ctx context.Context, p gitserver.Principal, sha string, progress io.Writer) (string, error) {
		actor := orch.Actor{ID: p.Actor}
		beam, err := o.DeployBeamFromGit(build.WithProgress(ctx, progress), actor, p.Beamhall, p.Beam, sha)
		if err != nil {
			return "", err
		}
		routes, err := st.ListRoutesByBeam(ctx, beam.ID)
		if err != nil {
			return "", nil
		}
		for i := len(routes) - 1; i >= 0; i-- {
			if routes[i].Status == domain.RouteActive {
				return "https://" + routes[i].Hostname, nil
			}
		}
		return "", nil
	}
}

// loadOrCreateSessionKey loads the Admin console's HMAC session key, generating
// a 32-byte key (0600) on first run so sessions survive restarts.
func loadOrCreateSessionKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := cryptorand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.0.0-dev"

func usageString() string {
	return `beamhalld — Beamhall infrastructure backplane

Usage:
  beamhalld                  run the appliance (configured via BEAMHALL_* env)
  beamhalld backup <path>    write an online backup archive
  beamhalld restore <path>   restore from a backup archive
  beamhalld admin <cmd>      IT provisioning (bootstrap, register-identity)
  beamhalld version          print the version and exit
  beamhalld help             show this help
`
}

func main() {
	// Subcommands run an action and exit; with no subcommand, run the server.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "backup":
			if err := runBackup(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "backup:", err)
				os.Exit(1)
			}
			return
		case "restore":
			if err := runRestore(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "restore:", err)
				os.Exit(1)
			}
			return
		case "admin":
			if err := runAdmin(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "admin:", err)
				os.Exit(1)
			}
			return
		case "version", "--version", "-v":
			fmt.Println("beamhalld", version)
			return
		case "help", "--help", "-h":
			fmt.Fprint(os.Stdout, usageString())
			return
		default:
			// Unknown command/flag: do NOT silently start the daemon (a typo'd
			// flag must not boot the server).
			fmt.Fprintf(os.Stderr, "beamhalld: unknown command or flag %q\n\n", os.Args[1])
			fmt.Fprint(os.Stderr, usageString())
			os.Exit(2)
		}
	}
	if err := run(); err != nil {
		// run() already logged the detail; exit non-zero for the supervisor.
		os.Exit(1)
	}
}

// runBackup writes an appliance backup. Usage: beamhalld backup <out.tar.gz>
// (data dir from BEAMHALL_DATA_DIR). Safe against a running appliance — the DB
// snapshot is online.
func runBackup(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: beamhalld backup <out.tar.gz>")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	// In production the secret root key lives out-of-band (BEAMHALL_SECRET_KEY_FILE),
	// not in the data dir; embed it from there so the backup is recoverable. Empty
	// falls back to the legacy <dataDir>/secret.key.
	if err := backup.Create(context.Background(), cfg.DataDir, cfg.SecretKeyFile, args[0], time.Now()); err != nil {
		return err
	}
	man, _ := backup.Verify(args[0])
	fmt.Printf("backup written: %s (db + secret key%s, %s)\n", args[0],
		map[bool]string{true: " + repos", false: ""}[man.HasRepos], man.CreatedAt)
	return nil
}

// runRestore restores an appliance backup. Usage:
// beamhalld restore <archive.tar.gz>. The appliance MUST be stopped first.
func runRestore(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: beamhalld restore <archive.tar.gz>  (stop the appliance first)")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	man, err := backup.Verify(args[0])
	if err != nil {
		return err
	}
	if err := backup.Restore(args[0], cfg.DataDir); err != nil {
		return err
	}
	fmt.Printf("restored %s into %s (backup from %s). Prior files saved as *.pre-restore.\n",
		args[0], cfg.DataDir, man.CreatedAt)
	if cfg.SecretKeyFile != "" {
		fmt.Printf("IMPORTANT: the recovered secret key is at %s/secret.key. This appliance reads its\n"+
			"key out-of-band from %s — install the recovered key there (0400 root:root)\n"+
			"before starting, e.g.:  install -m0400 %s/secret.key %s\n",
			cfg.DataDir, cfg.SecretKeyFile, cfg.DataDir, cfg.SecretKeyFile)
	}
	fmt.Println("Start beamhalld now.")
	return nil
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "err", err)
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	}))
	slog.SetDefault(logger)

	logger.Info("beamhalld starting",
		"version", version,
		"http_addr", cfg.HTTPAddr,
		"base_domain", cfg.BaseDomain,
		"data_dir", cfg.DataDir,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- control plane: store, vault, audit chain -------------------------
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		logger.Error("create data dir", "dir", cfg.DataDir, "err", err)
		return err
	}
	st, err := store.Open(ctx, filepath.Join(cfg.DataDir, "beamhall.db"))
	if err != nil {
		logger.Error("open control-plane store", "err", err)
		return err
	}
	defer st.Close()

	var rootKey *age.X25519Identity
	if cfg.SecretKeyFile != "" {
		// Production: the key is supplied out-of-band (systemd LoadCredential /
		// KMS). Load-only — never generate, so a missing key fails the boot.
		rootKey, err = secret.LoadKey(cfg.SecretKeyFile)
		if err != nil {
			logger.Error("load secret root key (out-of-band)", "path", cfg.SecretKeyFile, "err", err)
			return err
		}
		logger.Info("secret root key loaded out-of-band", "path", cfg.SecretKeyFile)
	} else {
		keyPath := filepath.Join(cfg.DataDir, "secret.key")
		var generated bool
		rootKey, generated, err = secret.LoadOrCreateKey(keyPath)
		if err != nil {
			logger.Error("load secret root key", "path", keyPath, "err", err)
			return err
		}
		if generated {
			logger.Warn("generated a new secret root key — all stored secrets are sealed to it; "+
				"production must supply this out-of-band via BEAMHALL_SECRET_KEY_FILE (systemd LoadCredential/KMS/TPM)",
				"path", keyPath)
		}
	}
	vault := secret.NewVault(rootKey, st)

	auditLog := audit.New(st)
	if issues, err := auditLog.Verify(ctx); err != nil {
		logger.Error("audit chain verification failed to run", "err", err)
		return err
	} else if len(issues) > 0 {
		// Tampering is surfaced loudly but does not brick the appliance: new
		// events still chain onto the current head, and the violations stay
		// on record here. Whether boot should hard-fail instead is an open
		// decision (docs/STATUS.md).
		for _, is := range issues {
			logger.Error("audit chain integrity violation", "seq", is.Seq, "reason", is.Reason)
		}
	} else {
		logger.Info("audit chain verified")
	}

	// --- runtime substrate: driver, gateway, scheduler --------------------
	drv, err := driver.NewDockerDriver(filepath.Join(cfg.DataDir, "secrets"))
	if err != nil {
		logger.Error("init docker driver", "err", err)
		return err
	}
	gwOpts := []gateway.Option{
		gateway.WithAdminURL(cfg.CaddyAdminURL),
		gateway.WithAskEndpoint(askURL(cfg.HTTPAddr)),
		gateway.WithListen(cfg.GatewayListen...),
		gateway.WithLogger(logger),
	}
	if !cfg.GatewayTLS {
		logger.Warn("gateway TLS disabled (BEAMHALL_GATEWAY_TLS=off) — beam routes serve plain HTTP")
		gwOpts = append(gwOpts, gateway.WithoutTLS())
	} else if cfg.GatewayTLSInternal {
		logger.Info("gateway TLS: internal CA (Caddy local CA) — install the gateway root CA on clients to trust beam/IdP certs")
		gwOpts = append(gwOpts, gateway.WithInternalTLS())
	}
	if cfg.BundledIDPUpstream != "" {
		idpHost := "idp." + cfg.BaseDomain
		gwOpts = append(gwOpts, gateway.WithStaticRoute(idpHost, cfg.BundledIDPUpstream))
		logger.Info("bundled IdP fronted by the gateway", "host", idpHost, "upstream", cfg.BundledIDPUpstream)
	}
	if cfg.BaseDomain != "" {
		// Front beamhalld's own endpoints (/mcp, /admin, /.well-known, /healthz)
		// through the gateway at the base domain, so they share the gateway TLS and
		// are reachable at https://<base-domain>/... — matching the OAuth audience
		// and the advertised Admin console URL (not just the raw :8443 control port).
		controlBackend := cfg.HTTPAddr
		if strings.HasPrefix(controlBackend, ":") {
			controlBackend = "127.0.0.1" + controlBackend
		}
		gwOpts = append(gwOpts, gateway.WithStaticRoute(cfg.BaseDomain, controlBackend))
		logger.Info("control endpoints fronted by the gateway", "host", cfg.BaseDomain, "upstream", controlBackend)
	}
	gw := gateway.New(gwOpts...)

	// The scheduler needs the orchestrator's PauseFunc and the orchestrator
	// needs the scheduler; bind the function after both exist (the scheduler
	// only fires after Start).
	var pauseFn scheduler.PauseFunc
	sched := scheduler.New(st.PauseStore(), func(ctx context.Context, beamID string) error {
		return pauseFn(ctx, beamID)
	}, scheduler.WithLogger(logger))

	// --- backplane: PEP + orchestrator + build + resources ----------------
	pep := policy.New(st, auditLog)
	egressSync := egressSyncFunc(cfg, st, drv, logger)
	repos := build.NewRepos(filepath.Join(cfg.DataDir, "repos")) // shared with the git server
	opts := []orch.Option{
		orch.WithLogger(logger),
		orch.WithEgressSync(egressSync),
		orch.WithPromoteApproval(cfg.PromoteApproval),
		orch.WithBuilder(&build.Pipeline{
			Repos: repos,
			Packer: &build.Packer{
				PackBin:    cfg.PackBin,
				DockerHost: cfg.BuildDockerHost,
				Builder:    cfg.CNBBuilder,
				Registry:   cfg.RegistryAddr,
				PullPolicy: cfg.PackPullPolicy,
				RunImage:   cfg.CNBRunImage,
			},
		}),
		orch.WithRepoRetirer(repos.Retire),
	}
	if cfg.PGAdminDSN != "" {
		opts = append(opts, orch.WithDatabaseProvisioner(&resource.PostgresProvisioner{
			AdminDSN: cfg.PGAdminDSN,
			BeamHost: cfg.PGBeamHost,
			Attach: func(ctx context.Context, network string) error {
				// Attach the managed Postgres container (named by PGBeamHost) to the
				// beam network so beams reach it as <PGBeamHost>:5432.
				return drv.ConnectContainerToNetwork(ctx, cfg.PGBeamHost, network)
			},
		}))
	} else {
		logger.Warn("BEAMHALL_PG_ADMIN_DSN unset — create_database is disabled")
	}
	// Owned-IdP administration (the admin_* IdP tools). Configured = the bundled
	// Keycloak; unconfigured = a bring-your-own-IdP deployment where the
	// orchestrator's default Disabled provider applies (Beamhall validates tokens
	// but administers no directory).
	if cfg.IDPAdminClientID != "" && cfg.IDPAdminClientSecret != "" {
		idpURL := cfg.IDPAdminURL
		if idpURL == "" && cfg.BundledIDPUpstream != "" {
			idpURL = "http://" + cfg.BundledIDPUpstream // default to the bundled IdP upstream
		}
		idp, ierr := identityadmin.NewKeycloak(identityadmin.KeycloakConfig{
			BaseURL: idpURL, Realm: cfg.IDPAdminRealm,
			ClientID: cfg.IDPAdminClientID, ClientSecret: cfg.IDPAdminClientSecret,
		})
		if ierr != nil {
			logger.Error("owned-IdP administration disabled (config error)", "err", ierr)
		} else {
			opts = append(opts, orch.WithIdentityAdmin(idp, cfg.IDPSensitiveAdmin))
			logger.Info("owned-IdP administration enabled", "realm", cfg.IDPAdminRealm,
				"sensitive_tier", cfg.IDPSensitiveAdmin)
		}
	} else {
		logger.Info("BEAMHALL_IDP_ADMIN_CLIENT_ID unset — owned-IdP administration disabled (BYO-IdP); admin_* IdP tools return a BYO-IdP notice")
	}
	orchestrator := orch.New(st, drv, gw, sched, vault, pep, auditLog, cfg.BaseDomain, opts...)
	pauseFn = orchestrator.PauseFunc()

	// --- boot reconciliation ----------------------------------------------
	if err := orchestrator.Boot(ctx); err != nil {
		// Caddy may simply not be up yet; the appliance still serves and the
		// operator sees exactly what is missing.
		logger.Error("boot route restore failed (is Caddy running?)", "err", err)
	}
	if err := sched.Start(ctx); err != nil {
		logger.Error("start pause scheduler", "err", err)
		return err
	}
	defer sched.Stop()
	if cfg.AuditRetentionDays > 0 {
		startAuditRetention(ctx, auditLog, cfg.AuditRetentionDays, logger)
	}
	if err := egressSync(ctx); err != nil {
		// Boot continues — there may be no bridges yet — but loudly: an
		// asserting failure with live bridges means degraded isolation.
		logger.Error("egress reconciliation FAILED — beam isolation may be degraded", "err", err)
	}

	// --- agent-facing surface: MCP + OAuth ---------------------------------
	mux := http.NewServeMux()
	mux.Handle("/internal/caddy-ask", gw.AskHandler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	const metadataPath = "/.well-known/oauth-protected-resource"
	if cfg.OAuthIssuer == "" {
		// Fail closed but keep the appliance bootable for first-run setup:
		// the MCP endpoint refuses until the IdP is configured. JWKS is optional
		// (resolved via OIDC discovery); only the issuer is mandatory.
		logger.Warn("BEAMHALL_OAUTH_ISSUER unset — the MCP endpoint and Admin console are disabled until the IdP is configured")
		mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "MCP is not available: this appliance has no identity provider configured (set BEAMHALL_OAUTH_ISSUER)", http.StatusServiceUnavailable)
		})
	} else {
		verifier, err := auth.NewVerifier(auth.Config{
			Issuer:       cfg.OAuthIssuer,
			Audience:     cfg.OAuthAudience,
			JWKSURL:      cfg.OAuthJWKSURL,
			DiscoveryURL: cfg.OAuthDiscoveryURL,
		})
		if err != nil {
			logger.Error("init token verifier", "err", err)
			return err
		}
		// Git smart-HTTP push transport: a shared one-time deploy-token store
		// between the MCP server (mints) and the git server (validates).
		gitBaseURL := cfg.AdminBaseURL // externally-reachable base, e.g. https://<host>
		if v := os.Getenv("BEAMHALL_GIT_BASE_URL"); v != "" {
			gitBaseURL = v
		}
		tokens := gitserver.NewTokenStore(0)
		ensureRepo := func(hall, beam string) error { _, err := repos.Ensure(hall, beam); return err }
		gitSvc := gitserver.New(filepath.Join(cfg.DataDir, "repos"), st, tokens,
			gitDeployer(orchestrator, st, logger), ensureRepo, logger)
		mux.Handle("/git/", gitSvc.Handler())

		mcpServer := mcp.New(orchestrator, st, version,
			mcp.WithLogger(logger), mcp.WithGitTransport(tokens, gitBaseURL),
			mcp.WithAdminRole(cfg.OAuthAdminRole))
		metadataURL := "https://" + cfg.BaseDomain + metadataPath
		mux.Handle("/mcp", mcpServer.Handler(verifier.Verify, metadataURL, allowedOrigins(cfg)))
		mux.Handle(metadataPath, mcp.MetadataHandler(cfg.OAuthAudience, []string{cfg.OAuthIssuer}))
		logger.Info("MCP server ready", "endpoint", "/mcp",
			"issuer", cfg.OAuthIssuer, "audience", cfg.OAuthAudience)

		// Admin console (same IdP, OIDC Authorization Code flow + session
		// cookie). Disabled without an admin client; a discovery/setup failure
		// is logged but does not brick the appliance.
		if cfg.AdminClientID == "" {
			logger.Warn("BEAMHALL_ADMIN_CLIENT_ID unset — the Admin console (/admin) is disabled")
		} else if sessionKey, kerr := loadOrCreateSessionKey(filepath.Join(cfg.DataDir, "admin-session.key")); kerr != nil {
			logger.Error("load admin session key", "err", kerr)
		} else if adminSrv, aerr := web.New(ctx, st, orchestrator, web.Config{
			BaseURL:      cfg.AdminBaseURL,
			Issuer:       cfg.OAuthIssuer,
			ClientID:     cfg.AdminClientID,
			ClientSecret: cfg.AdminClientSecret,
			Scopes:       cfg.AdminScopes,
			Verifier:     verifier,
			SessionKey:   sessionKey,
			Secure:       cfg.GatewayTLS,
			Logger:       logger,
		}); aerr != nil {
			logger.Error("Admin console disabled (init failed)", "err", aerr)
		} else {
			mux.Handle("/admin/", adminSrv.Handler())
			logger.Info("Admin console ready", "endpoint", "/admin", "base_url", cfg.AdminBaseURL)
		}
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("http listener up", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		logger.Error("http server failed", "err", err)
		return err
	case <-ctx.Done():
	}
	logger.Info("beamhalld shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutCtx)
}

// egressSyncFunc asserts the default-deny + allowlist iptables state for
// every beamhall whose bridge exists (PLAN §6: assert from policy, never
// accumulate drift). Runs at boot AND after every deploy — bridges are
// created lazily at deploy time, so boot-only assertion would leave a new
// beamhall's first workloads unprotected until the next restart. Linux-only
// by nature; a no-op elsewhere (dev hosts have no DOCKER-USER chain).
func egressSyncFunc(cfg config.Config, st *store.Store, drv *driver.DockerDriver, logger *slog.Logger) func(context.Context) error {
	rec := egress.New(cfg.EgressAlwaysDeny...)
	return func(ctx context.Context) error {
		if runtime.GOOS != "linux" {
			logger.Debug("egress reconciliation skipped (not linux)")
			return nil
		}
		halls, err := st.ListBeamhalls(ctx)
		if err != nil {
			return fmt.Errorf("egress: list beamhalls: %w", err)
		}
		var policies []egress.Policy
		for _, bh := range halls {
			bridge, err := drv.NetworkBridge(ctx, "bh-"+string(bh.ID))
			if err != nil {
				continue // no network yet — nothing to protect or break
			}
			policies = append(policies, egress.Policy{
				Bridge: bridge,
				Allow:  bh.NetworkPolicy.EgressAllowlist,
			})
		}
		if err := rec.Reconcile(ctx, policies); err != nil {
			return err
		}
		logger.Info("egress policy asserted", "bridges", len(policies))
		return nil
	}
}

// askURL is where Caddy's on-demand-TLS ask endpoint reaches this process.
func askURL(httpAddr string) string {
	host, port, err := splitHostPort(httpAddr)
	if err != nil || host == "" {
		host = "127.0.0.1"
	}
	return "http://" + host + ":" + port + "/internal/caddy-ask"
}

func splitHostPort(addr string) (string, string, error) {
	u, err := url.Parse("http://" + addr)
	if err != nil {
		return "", "", err
	}
	return u.Hostname(), u.Port(), nil
}

// allowedOrigins are the hostnames browser-originated MCP requests may come
// from: the appliance's own names (DNS-rebinding defense, PLAN §6).
func allowedOrigins(cfg config.Config) []string {
	origins := []string{cfg.BaseDomain}
	if u, err := url.Parse(cfg.OAuthAudience); err == nil && u.Hostname() != "" {
		origins = append(origins, u.Hostname())
	}
	return origins
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
