//go:build linux

package aissh

import (
	"strings"
	"testing"
)

func TestLinuxStartupStates(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want startupStatus
	}{
		{"LoadState=not-found\nActiveState=inactive\nUnitFileState=", startupStatus{}},
		{"LoadState=loaded\nActiveState=active\nUnitFileState=enabled", startupStatus{true, true, true}},
		{"LoadState=loaded\nActiveState=failed\nUnitFileState=disabled", startupStatus{Installed: true}},
	} {
		b := newStartupBackend(func(string, ...string) ([]byte, error) { return []byte(tc.out), nil })
		s, err := b.status()
		if err != nil || s != tc.want {
			t.Fatalf("%+v %v", s, err)
		}
	}
	unit := linuxStartupUnit(StartupConfig{User: "alice"})
	for _, s := range []string{`User="alice"`, `"/usr/local/lib/aissh/aisshc" --service-run`, "Restart=always", "WantedBy=multi-user.target"} {
		if !strings.Contains(unit, s) {
			t.Fatalf("missing %q", s)
		}
	}
	if systemdQuote("a%b") != `"a%%b"` {
		t.Fatal("specifier escaping")
	}
}
