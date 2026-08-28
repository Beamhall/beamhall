//go:build !linux

package driver

// isTmpfs always reports true off Linux: the production runtime is
// Linux-only (the driver shells out to Docker + gVisor/runc there), so the
// tmpfs assertion in NewDockerDriver is meaningless on a dev/build machine —
// treat it as satisfied rather than blocking `go build`/`go test` elsewhere.
func isTmpfs(string) (bool, error) { return true, nil }
