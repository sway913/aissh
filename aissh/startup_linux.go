//go:build linux

package aissh

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const startupUnit = "aisshc.service"
const startupUnitPath = "/etc/systemd/system/aisshc.service"

type linuxStartup struct{ run startupCommand }

func newStartupBackend(run startupCommand) startupBackend { return &linuxStartup{run} }
func startupAdmin() bool                                  { return os.Geteuid() == 0 }
func (b *linuxStartup) status() (startupStatus, error) {
	out, err := b.run("systemctl", "show", startupUnit, "--property=LoadState,ActiveState,UnitFileState", "--no-pager")
	if err != nil {
		return startupStatus{}, err
	}
	fields := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(l, "=")
		if ok {
			fields[k] = v
		}
	}
	if fields["LoadState"] == "not-found" {
		return startupStatus{}, nil
	}
	if fields["LoadState"] != "loaded" {
		return startupStatus{}, fmt.Errorf("invalid aisshc unit state: %s", out)
	}
	return startupStatus{true, fields["ActiveState"] == "active", fields["UnitFileState"] == "enabled"}, nil
}
func systemdQuote(s string) string { return strconv.Quote(strings.ReplaceAll(s, "%", "%%")) }
func linuxStartupUnit(c StartupConfig) string {
	_, exe, _ := startupPaths("linux")
	return fmt.Sprintf(`[Unit]
Description=aissh automatic SSH client
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=%d
ExecStart=%s --service-run
Restart=always
RestartSec=10
UMask=0077
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`, c.UID, systemdQuote(exe))
}
func (b *linuxStartup) install(c StartupConfig) error {
	if err := os.WriteFile(startupUnitPath, []byte(linuxStartupUnit(c)), 0644); err != nil {
		return err
	}
	_, err := b.run("systemctl", "daemon-reload")
	return err
}
func (b *linuxStartup) start() error {
	_, err := b.run("systemctl", "enable", "--now", startupUnit)
	return err
}
func (b *linuxStartup) stop() error { _, err := b.run("systemctl", "stop", startupUnit); return err }
func (b *linuxStartup) remove() error {
	if _, err := b.run("systemctl", "disable", startupUnit); err != nil {
		return err
	}
	if err := os.Remove(startupUnitPath); err != nil {
		return err
	}
	_, err := b.run("systemctl", "daemon-reload")
	return err
}

func protectStartupDirectory(dir string) error {
	if err := os.Chown(dir, 0, 0); err != nil {
		return err
	}
	return os.Chmod(dir, 0755)
}
