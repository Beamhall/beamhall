package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// fakeRelease serves a GoReleaser-style release: a tarball containing an
// executable "beamhalld" (a shell script that prints the version) plus a
// checksums.txt. corrupt=true makes checksums.txt list the wrong digest.
func fakeRelease(t *testing.T, bareVer string, corrupt bool) *httptest.Server {
	t.Helper()
	asset := fmt.Sprintf("beamhall_%s_linux_amd64.tar.gz", bareVer)

	// A runnable "beamhalld" that prints "beamhalld <ver>" on `version`.
	script := "#!/bin/sh\necho \"beamhalld " + bareVer + "\"\n"
	var tarbuf bytes.Buffer
	gz := gzip.NewWriter(&tarbuf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "beamhalld", Mode: 0o755, Size: int64(len(script)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte(script))
	tw.Close()
	gz.Close()
	tgz := tarbuf.Bytes()

	sum := sha256.Sum256(tgz)
	digest := hex.EncodeToString(sum[:])
	if corrupt {
		digest = strings.Repeat("0", 64)
	}
	checksums := digest + "  " + asset + "\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/v"+bareVer+"/"+asset, func(w http.ResponseWriter, r *http.Request) { w.Write(tgz) })
	mux.HandleFunc("/v"+bareVer+"/checksums.txt", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(checksums)) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newRelease(t *testing.T, srv *httptest.Server, current string) Release {
	return Release{
		BaseURL: srv.URL, InstallPath: "/usr/local/bin/beamhalld",
		StagingDir: t.TempDir(), GOOS: "linux", GOARCH: "amd64",
		Current: current, HTTP: srv.Client(),
	}
}

func TestStageVerifiesAndStages(t *testing.T) {
	srv := fakeRelease(t, "0.1.11", false)
	r := newRelease(t, srv, "v0.1.10")
	res, err := r.Stage(context.Background(), "v0.1.11")
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if res.Version != "v0.1.11" {
		t.Errorf("version = %q", res.Version)
	}
	if _, err := os.Stat(res.StagedPath); err != nil {
		t.Errorf("staged binary missing: %v", err)
	}
	if !strings.Contains(res.ApplyCmd, "systemctl restart beamhalld") || !strings.Contains(res.ApplyCmd, ".rollback") {
		t.Errorf("apply cmd: %q", res.ApplyCmd)
	}
	if !strings.Contains(res.RollbackCmd, ".rollback") {
		t.Errorf("rollback cmd: %q", res.RollbackCmd)
	}
}

func TestStageRejectsChecksumMismatch(t *testing.T) {
	srv := fakeRelease(t, "0.1.11", true) // checksums.txt lists a wrong digest
	r := newRelease(t, srv, "v0.1.10")
	_, err := r.Stage(context.Background(), "v0.1.11")
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("want checksum mismatch, got %v", err)
	}
}

func TestStageRejectsBadVersionAndSameVersion(t *testing.T) {
	srv := fakeRelease(t, "0.1.11", false)
	r := newRelease(t, srv, "v0.1.10")
	if _, err := r.Stage(context.Background(), "../../etc/passwd"); err == nil {
		t.Error("must reject a non-version target")
	}
	if _, err := r.Stage(context.Background(), "v0.1.10"); err == nil {
		t.Error("must reject upgrading to the current version")
	}
}

func TestDisabledStager(t *testing.T) {
	var s Stager = Disabled{Version: "v0.1.10"}
	if s.Enabled() {
		t.Error("Disabled must report not enabled")
	}
	if s.CurrentVersion() != "v0.1.10" {
		t.Error("CurrentVersion")
	}
	if _, err := s.Stage(context.Background(), "v0.1.11"); err != ErrNotEnabled {
		t.Errorf("want ErrNotEnabled, got %v", err)
	}
}
