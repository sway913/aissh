//go:build !linux && !darwin && !windows

package aissh

import "fmt"

type unsupportedStartup struct{}

func newStartupBackend(startupCommand) startupBackend { return unsupportedStartup{} }
func startupAdmin() bool                              { return false }
func (unsupportedStartup) status() (startupStatus, error) {
	return startupStatus{}, fmt.Errorf("boot startup is unsupported on this platform; use --foreground")
}
func (unsupportedStartup) install(StartupConfig) error { return nil }
func (unsupportedStartup) start() error                { return nil }
func (unsupportedStartup) stop() error                 { return nil }
func (unsupportedStartup) remove() error               { return nil }

func protectStartupDirectory(string) error { return fmt.Errorf("unsupported startup platform") }
