//go:build linux

package driver

import (
	"os"
	"testing"
)

// diskBackedDir returns a temp dir that is NOT on tmpfs, for the negative
// cases below. t.TempDir() is only disk-backed where /tmp is — Ubuntu ≥24.10
// mounts /tmp as tmpfs — so fall back to /var/tmp, which the FHS keeps on
// persistent storage. Skips if no disk-backed location exists.
func diskBackedDir(t *testing.T) string {
	t.Helper()
	if dir := t.TempDir(); !mustIsTmpfs(t, dir) {
		return dir
	}
	if !mustIsTmpfs(t, "/var/tmp") {
		dir, err := os.MkdirTemp("/var/tmp", "bh-tmpfs-test-")
		if err != nil {
			t.Fatalf("mkdir under /var/tmp: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return dir
	}
	t.Skip("no disk-backed filesystem available for the negative case")
	return ""
}

func mustIsTmpfs(t *testing.T, path string) bool {
	t.Helper()
	ok, err := isTmpfs(path)
	if err != nil {
		t.Fatalf("isTmpfs(%s): %v", path, err)
	}
	return ok
}

// TestIsTmpfs: /dev/shm is tmpfs on every standard Linux system; a
// disk-backed dir must not be misreported as tmpfs.
func TestIsTmpfs(t *testing.T) {
	if !mustIsTmpfs(t, "/dev/shm") {
		t.Fatal("/dev/shm not detected as tmpfs")
	}
	if mustIsTmpfs(t, diskBackedDir(t)) {
		t.Fatal("a disk-backed dir was reported as tmpfs")
	}
}

// TestNewDockerDriverFailsClosedOffTmpfs is a regression test: the
// driver must refuse to start rather than silently stage decrypted secrets
// on persistent disk.
func TestNewDockerDriverFailsClosedOffTmpfs(t *testing.T) {
	if _, err := NewDockerDriver(diskBackedDir(t)); err == nil {
		t.Fatal("NewDockerDriver accepted a non-tmpfs secrets root")
	}
}
