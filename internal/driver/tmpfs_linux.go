//go:build linux

package driver

import "syscall"

// tmpfsMagic is TMPFS_MAGIC from linux/magic.h — the f_type Statfs reports
// for a tmpfs mount.
const tmpfsMagic = 0x01021994

// isTmpfs reports whether path resolves onto a tmpfs (RAM-backed) mount. Used
// to enforce that decrypted secrets are staged off persistent disk.
func isTmpfs(path string) (bool, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false, err
	}
	return int64(st.Type) == tmpfsMagic, nil
}
