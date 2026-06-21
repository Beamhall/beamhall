package resource

// Lab integration test: real Postgres provisioning against the appliance
// database (bh-postgres on the lab VM — see scripts/lab-bootstrap.sh).
// Proves the db-per-beam isolation model: the scoped role works on its own
// database, cannot touch a sibling database, and a workload on a Beamhall
// network attached via the driver reaches the server by DNS name with the
// DSN exactly as sealed.
//
//	GOOS=linux GOARCH=amd64 go test -c ./internal/resource -o /tmp/resource.test
//	scp /tmp/resource.test root@"$BEAMHALL_TEST_HOST":/tmp/
//	ssh root@"$BEAMHALL_TEST_HOST" 'BEAMHALL_DOCKER_IT=1 /tmp/resource.test -test.v'

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/driver"
)

func adminDSN() string {
	if v := os.Getenv("BEAMHALL_PG_ADMIN_DSN"); v != "" {
		return v
	}
	// Lab default: loopback-published admin port of bh-postgres (lab-only
	// fixed credential; the production appliance generates its own).
	return "postgres://postgres:beamhall-lab-admin@127.0.0.1:5433/postgres?sslmode=disable"
}

// adminSide rewrites a beam-facing DSN (bh-postgres:5432) to the loopback
// admin port so the test harness, which runs on the host, can dial it.
func adminSide(dsn string) string {
	return strings.Replace(dsn, "@bh-postgres:5432/", "@127.0.0.1:5433/", 1)
}

func TestPostgresProvisionIsolationAndReachability(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the Postgres integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	drv, err := driver.NewDockerDriver(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatalf("NewDockerDriver: %v", err)
	}
	const testNet = "bh-pg-it"
	p := &PostgresProvisioner{
		AdminDSN: adminDSN(),
		BeamHost: "bh-postgres",
		Attach: func(ctx context.Context, network string) error {
			return drv.ConnectContainerToNetwork(ctx, "bh-postgres", network)
		},
	}

	one, err := p.Provision(ctx, Request{BeamhallSlug: "it", BeamSlug: "alpha", Name: "main", Network: testNet})
	if err != nil {
		t.Fatalf("Provision alpha: %v", err)
	}
	two, err := p.Provision(ctx, Request{BeamhallSlug: "it", BeamSlug: "beta", Name: "main", Network: testNet})
	if err != nil {
		t.Fatalf("Provision beta: %v", err)
	}
	defer func() {
		_ = p.Drop(context.Background(), one)
		_ = p.Drop(context.Background(), two)
		// Detach before removing the test network (the server stays on its
		// home network).
		_ = drv.RemoveNetwork(context.Background(), testNet)
	}()

	// The scoped role works on its own database.
	db1, err := sql.Open("pgx", adminSide(one.DSN))
	if err != nil {
		t.Fatal(err)
	}
	defer db1.Close()
	if _, err := db1.ExecContext(ctx, `CREATE TABLE t (v int); INSERT INTO t VALUES (42)`); err != nil {
		t.Fatalf("scoped role cannot use its own database: %v", err)
	}
	var v int
	if err := db1.QueryRowContext(ctx, `SELECT v FROM t`).Scan(&v); err != nil || v != 42 {
		t.Fatalf("round trip = %d, %v", v, err)
	}
	t.Logf("scoped role OK on own database %s", one.Database)

	// Isolation: alpha's role (correct credentials) cannot connect to beta's
	// database. Anchor the replacement on the path?query segment — the role
	// name in the URL also contains the database name.
	crossDSN := strings.Replace(adminSide(one.DSN), "/"+one.Database+"?", "/"+two.Database+"?", 1)
	cross, err := sql.Open("pgx", crossDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer cross.Close()
	if err := cross.PingContext(ctx); err == nil {
		t.Fatal("alpha's role connected to beta's database — isolation broken")
	} else {
		t.Logf("cross-database access denied as designed: %v", err)
	}

	// Beam-side reachability: a workload on the attached Beamhall network
	// reaches bh-postgres:5432 with the DSN exactly as sealed. psql runs as
	// the workload command; exit 0 = connected and queried.
	h, err := drv.Deploy(ctx, driver.DeploySpec{
		BeamID:      "pg-client-it",
		BeamhallID:  "it",
		ImageDigest: "postgres:17-alpine",
		Command:     []string{"psql", one.DSN, "-c", "SELECT 'beamhall db ok'"},
		Network:     driver.NetworkPolicy{BeamhallNetwork: testNet},
		Security:    driver.SecurityProfile{RuntimeClass: driver.RuntimeRunc, CapDrop: []string{"ALL"}, NoNewPrivileges: true},
		Resources:   driver.ResourceLimits{MemBytes: 256 << 20, PidsMax: 128},
	})
	if err != nil {
		t.Fatalf("deploy psql client: %v", err)
	}
	defer drv.Destroy(context.Background(), h)
	if err := drv.Start(ctx, h); err != nil {
		t.Fatalf("start psql client: %v", err)
	}
	deadline := time.After(60 * time.Second)
	for {
		st, err := drv.Status(ctx, h)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if st.State == driver.WorkloadExited {
			if st.ExitCode == nil || *st.ExitCode != 0 {
				t.Fatalf("psql client exited %v — beam-side DSN unreachable", st.ExitCode)
			}
			t.Log("beam-side reachability OK: workload on the attached network queried via the sealed DSN")
			break
		}
		select {
		case <-deadline:
			t.Fatal("psql client did not finish")
		case <-time.After(time.Second):
		}
	}

	// Drop removes both database and role.
	if err := p.Drop(ctx, one); err != nil {
		t.Fatalf("Drop: %v", err)
	}
	if db := sql.Open; db != nil { // re-dial after drop must fail
		gone, _ := sql.Open("pgx", adminSide(one.DSN))
		defer gone.Close()
		if err := gone.PingContext(ctx); err == nil {
			t.Fatal("database still reachable after Drop")
		}
	}
}
