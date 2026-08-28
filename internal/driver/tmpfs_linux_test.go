//go:build linux

package driver

import "testing"

// TestIsTmpfs is part of the regression coverage:
// /dev/shm is
// tmpfs on every standard Linux system, t.TempDir() is ordinary disk-backed
// storage (under the module's build/work dir, not a tmpfs mount).
func TestIsTmpfs(t *testing.T) {
	if ok, err := isTmpfs("/dev/shm"); err != nil {
		t.Fatalf("isTmpfs(/dev/shm): %v", err)
	} else if !ok {
		t.Fatal("/dev/shm not detected as tmpfs")
	}

	if ok, err := isTmpfs(t.TempDir()); err != nil {
		t.Fatalf("isTmpfs(t.TempDir()): %v", err)
	} else if ok {
		t.Fatal("a disk-backed temp dir was reported as tmpfs")
	}
}

// TestNewDockerDriverFailsClosedOffTmpfs is a regression test: the
// driver must refuse to start rather than silently stage decrypted secrets
// on persistent disk.
func TestNewDockerDriverFailsClosedOffTmpfs(t *testing.T) {
	if _, err := NewDockerDriver(t.TempDir()); err == nil {
		t.Fatal("NewDockerDriver accepted a non-tmpfs secrets root (H2 regression)")
	}
}
