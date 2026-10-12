package aissh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminDeviceAutomaticAccessAndDemotion(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir)
	a := mustRegister(t, s, "00:11:22:33:44:51", "admin")
	b := mustRegister(t, s, "00:11:22:33:44:52", "manual")
	c := mustRegister(t, s, "00:11:22:33:44:53", "automatic")
	if err := s.SetRule(a.ID, b.ID, true); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Config(a.ID, a.Token)
	if err := s.SetAdmin(a.ID, true); err != nil {
		t.Fatal(err)
	}
	d := mustRegister(t, s, "00:11:22:33:44:54", "future")
	cfg, _ := s.Config(a.ID, a.Token)
	if len(cfg.Grants) != 3 {
		t.Fatalf("expected all other devices: %+v", cfg.Grants)
	}
	for _, g := range cfg.Grants {
		if g.Target == a.ID {
			t.Fatal("self grant")
		}
		if g.Target == b.ID && g.Port != before.Grants[0].Port {
			t.Fatal("manual port changed")
		}
	}
	back, _ := s.Config(d.ID, d.Token)
	if len(back.Grants) != 0 {
		t.Fatal("admin access must be one way")
	}
	if err := s.SetRule(a.ID, c.ID, false); err == nil {
		t.Fatal("automatic permission can be individually removed")
	}
	left, right := net.Pipe()
	defer right.Close()
	tracked, err := s.Track(left, a.ID, c.ID, runID(a.Token))
	if err != nil {
		t.Fatal(err)
	}
	defer tracked.Close()
	if err = s.SetAdmin(a.ID, false); err != nil {
		t.Fatal(err)
	}
	right.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = right.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("automatic connection not revoked: %v", err)
	}
	cfg, _ = s.Config(a.ID, a.Token)
	if len(cfg.Grants) != 1 || cfg.Grants[0].Target != b.ID || cfg.Grants[0].Port != before.Grants[0].Port {
		t.Fatalf("manual permission not preserved: %+v", cfg)
	}
	s.SetAdmin(a.ID, true)
	s.SetEnabled(c.ID, false)
	cfg, _ = s.Config(a.ID, a.Token)
	for _, g := range cfg.Grants {
		if g.Target == c.ID {
			t.Fatal("disabled target reachable")
		}
	}
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ds, _ := reopened.Snapshot()
	for _, dev := range ds {
		if dev.ID == a.ID && !dev.Admin {
			t.Fatal("role not persisted")
		}
	}
	s.SetEnabled(a.ID, false)
	if _, err = s.Config(a.ID, a.Token); err != ErrDenied {
		t.Fatal("disabled administrator accepted")
	}
}

func TestAdminRoleSynchronizationAndSaveFailure(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	a := mustRegister(t, s, "00:11:22:33:44:51", "A")
	b := mustRegister(t, s, "00:11:22:33:44:52", "B")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s.signingKey = priv
	replica, _ := OpenStore(t.TempDir())
	replica.replica = true
	replica.federation = &FederationConfig{PublicKey: base64.StdEncoding.EncodeToString(pub)}
	if err := s.SetAdmin(a.ID, true); err != nil {
		t.Fatal(err)
	}
	signed, _ := s.signedSnapshot()
	if err := replica.applyPolicy(signed, false); err != nil {
		t.Fatal(err)
	}
	ra := mustRegister(t, replica, "00:11:22:33:44:51", "A")
	if len(ra.Grants) != 1 || ra.Grants[0].Target != b.ID {
		t.Fatal("automatic access not synchronized")
	}
	if err := replica.SetAdmin(b.ID, true); err == nil {
		t.Fatal("replica modified role")
	}
	s.SetAdmin(a.ID, false)
	signed, _ = s.signedSnapshot()
	replica.applyPolicy(signed, false)
	cfg, _ := replica.Config(ra.ID, ra.Token)
	if len(cfg.Grants) != 0 {
		t.Fatal("demotion not synchronized")
	}
	oldPath := s.path
	s.path = filepath.Join(t.TempDir(), "missing", "devices.json")
	if err := s.SetAdmin(a.ID, true); err == nil {
		t.Fatal("save failure ignored")
	}
	if s.state.Devices[a.ID].Admin || len(s.state.Rules) != 0 {
		t.Fatal("failed role change persisted in memory")
	}
	s.path = oldPath
	s.SetAdmin(a.ID, true)
	s.path = filepath.Join(t.TempDir(), "missing", "devices.json")
	_, err := s.Register(registration("00:11:22:33:44:53", "C"))
	if err == nil || len(s.state.Devices) != 2 || len(s.state.Rules) != 1 {
		t.Fatal("registration failure did not roll back automatic rules")
	}
}

func TestAdminDeviceEndpointAndRegistrationCannotElevate(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	a := mustRegister(t, s, "00:11:22:33:44:51", "A")
	h := AdminHandler(s, "test-password")
	for _, auth := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodPost, "/api/devices/admin", strings.NewReader(`{"id":"`+a.ID+`","admin":true}`))
		r.Header.Set("Content-Type", "application/json")
		if auth {
			r.SetBasicAuth("admin", "test-password")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if auth && w.Code != 200 || !auth && w.Code != 401 {
			t.Fatalf("status %d", w.Code)
		}
	}
	body, _ := json.Marshal(registration("00:11:22:33:44:52", "B"))
	var data map[string]any
	json.Unmarshal(body, &data)
	data["admin"] = true
	body, _ = json.Marshal(data)
	r := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	DeviceHandler(s).ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("device requested its own admin role")
	}
	if _, err := os.Stat(s.path); err != nil {
		t.Fatal(err)
	}
}
