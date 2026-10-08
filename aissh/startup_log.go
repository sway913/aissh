package aissh

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// StartupLog captures Windows task diagnostics, which have no visible terminal.
func StartupLog() error {
	dir, _, _ := startupPaths(runtime.GOOS)
	path := filepath.Join(dir, "client.log")
	if st, err := os.Stat(path); err == nil && st.Size() > 10<<20 {
		_ = os.Remove(path + ".old")
		if err = os.Rename(path, path+".old"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	os.Stdout, os.Stderr = f, f
	log.SetOutput(f)
	return nil
}
