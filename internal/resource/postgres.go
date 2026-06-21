// Package resource provisions managed primitives for beams (PLAN §5.7
// create_database; §6 db-per-beam scoped roles). Postgres is the MVP
// provider: one appliance-owned Postgres server; every database gets its own
// LOGIN role and PUBLIC access revoked, so a beam's credentials reach exactly
// its own database and nothing else. Connection strings never pass through
// the agent — the orchestrator seals them into the vault and they surface
// only as files inside the workload.
package resource

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx"
)

// Request asks for one database for a beam.
type Request struct {
	BeamhallSlug string
	BeamSlug     string
	// Name distinguishes multiple databases per beam ("main", "analytics").
	// It becomes part of the role/db identifiers and the secret key.
	Name string
	// Network is the beamhall bridge the consuming beam runs on; the
	// provisioner ensures the database server is reachable from it.
	Network string
}

// Provisioned is the result: the DSN (sealed into the vault by the caller,
// never returned to agents) and the backing identifiers for teardown.
type Provisioned struct {
	DSN      string
	Database string
	Role     string
}

// nameRe bounds identifier parts: lowercase alphanumerics, inner underscores
// or hyphens (hyphens map to underscores in SQL identifiers).
var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,30}[a-z0-9])?$`)

// PostgresProvisioner provisions scoped databases on the appliance Postgres.
type PostgresProvisioner struct {
	// AdminDSN connects the backplane to Postgres with CREATEDB/CREATEROLE
	// rights (loopback-published admin port; beams never see it).
	AdminDSN string
	// BeamHost/BeamPort is the address workloads use to reach the server —
	// the container's DNS name on the beamhall bridge, not the admin address.
	BeamHost string
	BeamPort int
	// Attach makes the server reachable from a beamhall network (connects the
	// Postgres container to that bridge). Idempotent; nil = already reachable.
	Attach func(ctx context.Context, network string) error
}

// Provision creates role + database and returns the scoped DSN. Idempotency:
// a second call for the same identifiers fails (the database exists) — the
// orchestrator's Resource row uniqueness is the real guard; this keeps SQL
// simple and never silently reuses credentials.
func (p *PostgresProvisioner) Provision(ctx context.Context, req Request) (Provisioned, error) {
	for _, part := range []string{req.BeamhallSlug, req.BeamSlug, req.Name} {
		if !nameRe.MatchString(part) {
			return Provisioned{}, fmt.Errorf("invalid identifier part %q", part)
		}
	}
	dbName := sqlIdent(fmt.Sprintf("bh_%s_%s_%s", req.BeamhallSlug, req.BeamSlug, req.Name))
	role := dbName + "_rw"
	if len(role) > 63 {
		return Provisioned{}, fmt.Errorf("identifier %q exceeds Postgres's 63-byte limit; shorten the slugs/name", role)
	}
	password, err := randomPassword()
	if err != nil {
		return Provisioned{}, err
	}

	admin, err := sql.Open("pgx", p.AdminDSN)
	if err != nil {
		return Provisioned{}, fmt.Errorf("admin connection: %w", err)
	}
	defer admin.Close()

	// Identifiers are validated above and double-quoted; the password is a
	// literal (hex, no quoting hazards) — CREATE ROLE cannot take placeholders.
	stmts := []string{
		fmt.Sprintf(`CREATE ROLE %q LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`, role, password),
		fmt.Sprintf(`CREATE DATABASE %q OWNER %q`, dbName, role),
		fmt.Sprintf(`REVOKE ALL ON DATABASE %q FROM PUBLIC`, dbName),
	}
	for i, stmt := range stmts {
		if _, err := admin.ExecContext(ctx, stmt); err != nil {
			// Roll back the role if the database creation failed after it.
			if i > 0 {
				_, _ = admin.ExecContext(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %q`, role))
			}
			return Provisioned{}, fmt.Errorf("provision %s: %w", dbName, err)
		}
	}

	if p.Attach != nil && req.Network != "" {
		if err := p.Attach(ctx, req.Network); err != nil {
			return Provisioned{}, fmt.Errorf("attach database server to %s: %w", req.Network, err)
		}
	}

	port := p.BeamPort
	if port == 0 {
		port = 5432
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		url.QueryEscape(role), password, p.BeamHost, port, dbName)
	return Provisioned{DSN: dsn, Database: dbName, Role: role}, nil
}

// Drop tears a provisioned database and its role down (resource deletion;
// archival/backup is the caller's concern).
func (p *PostgresProvisioner) Drop(ctx context.Context, pr Provisioned) error {
	admin, err := sql.Open("pgx", p.AdminDSN)
	if err != nil {
		return err
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %q WITH (FORCE)`, pr.Database)); err != nil {
		return err
	}
	_, err = admin.ExecContext(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %q`, pr.Role))
	return err
}

// sqlIdent maps slug hyphens to underscores (hyphens would need quoting in
// every client; underscores keep DSNs friction-free).
func sqlIdent(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c == '-' {
			out[i] = '_'
		}
	}
	return string(out)
}

// randomPassword is 192 bits of hex — safe inside a quoted SQL literal and a
// DSN without escaping.
func randomPassword() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
