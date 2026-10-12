//go:build windows

package aissh

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

func lockAgentIdentity(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "identity.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var o windows.Overlapped
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &o)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("aisshc already owns this identity; stop the scheduled task before using --foreground: %w", err)
	}
	return func() { windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &o); f.Close() }, nil
}

func adoptIdentityUser(*StartupConfig) error { return nil }
