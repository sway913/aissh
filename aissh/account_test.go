package aissh

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHUsername(t *testing.T) {
	for _, tc := range []struct{ os, host, account, want string }{
		{"windows", "DESKTOP-ABC", `DESKTOP-ABC\ztz`, "ztz"},
		{"windows", "desktop-abc", `DESKTOP-ABC\Local User`, "Local User"},
		{"windows", "DESKTOP-ABC", `.\ztz`, "ztz"},
		{"windows", "DESKTOP-ABC", `CORP\alice`, `CORP\alice`},
		{"windows", "DESKTOP-ABC", "ztz", "ztz"},
		{"darwin", "mac.local", "ztz", "ztz"},
		{"linux", "host", "alice", "alice"},
	} {
		if got := sshUsername(tc.os, tc.host, tc.account); got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.account, got, tc.want)
		}
	}
}

func TestRegistrationUpdatesAccountWithoutChangingIdentityOrRules(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := registration("00:11:22:33:44:55", "old-host")
	original, err := s.Register(r)
	if err != nil {
		t.Fatal(err)
	}
	b := mustRegister(t, s, "00:11:22:33:44:56", "B")
	if err = s.SetRule(b.ID, original.ID, true); err != nil {
		t.Fatal(err)
	}
	r.Name, r.OS, r.Username, r.Account = "DESKTOP-ABC", "windows", "ztz", `DESKTOP-ABC\ztz`
	updated, err := s.Register(r)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != original.ID || updated.Secret != original.Secret {
		t.Fatal("account update changed device identity")
	}
	reopened, err := OpenStore(filepath.Dir(s.path))
	if err != nil {
		t.Fatal(err)
	}
	devices, rules := reopened.Snapshot()
	if len(rules) != 1 || rules[0].Target != original.ID {
		t.Fatal("account update lost permissions")
	}
	var found bool
	for _, d := range devices {
		if d.ID == original.ID {
			found = true
			if d.Username != r.Username || d.Account != r.Account || d.Name != r.Name {
				t.Fatalf("account not persisted: %+v", d)
			}
		}
	}
	if !found {
		t.Fatal("updated device missing")
	}
	// Registration from an older binary must not erase the account metadata.
	r.Username, r.Account = "", ""
	if _, err = s.Register(r); err != nil {
		t.Fatal(err)
	}
	devices, _ = s.Snapshot()
	for _, d := range devices {
		if d.ID == original.ID && d.Username != "ztz" {
			t.Fatal("old client erased username")
		}
	}
	for _, invalid := range []string{strings.Repeat("x", 257), "name\nheader", "bad\x00user"} {
		r.Username = invalid
		if _, err = s.Register(r); err == nil {
			t.Fatalf("invalid username accepted: %q", invalid)
		}
	}
}
