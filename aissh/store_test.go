package aissh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/fatedier/frp/pkg/msg"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fingerprint(mac string) Fingerprint {
	h := sha256.Sum256([]byte("test-hardware"))
	return Fingerprint{MACs: []string{mac}, Hardware: []string{hex.EncodeToString(h[:])}}
}
func registration(mac, name string) Registration {
	return Registration{Fingerprint: fingerprint(mac), Name: name, OS: "test"}
}
func mustRegister(t *testing.T, s *Store, mac, name string) DeviceConfig {
	t.Helper()
	c, e := s.Register(registration(mac, name))
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestHardwareIdentity(t *testing.T) {
	f := fingerprint("00:11:22:33:44:55")
	a, e := f.ID()
	if e != nil {
		t.Fatal(e)
	}
	f.MACs = []string{"00-11-22-33-44-55"}
	b, _ := f.ID()
	if a != b {
		t.Fatal("MAC formatting changed identity")
	}
	f.MACs = []string{"00:11:22:33:44:56"}
	c, _ := f.ID()
	if a == c {
		t.Fatal("MAC did not contribute to identity")
	}
	f = fingerprint("00:11:22:33:44:55")
	f.Hardware = nil
	c, _ = f.ID()
	if a == c {
		t.Fatal("hardware did not contribute to identity")
	}
	if _, e = (Fingerprint{MACs: []string{"ff:ff:ff:ff:ff:ff"}}).ID(); e == nil {
		t.Fatal("multicast MAC accepted")
	}
}
func TestRegistrationPermissionsPersistenceAndRevocation(t *testing.T) {
	dir := t.TempDir()
	s, e := OpenStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	a := mustRegister(t, s, "00:11:22:33:44:55", "A")
	b := mustRegister(t, s, "00:11:22:33:44:56", "B")
	if len(a.Grants) != 0 {
		t.Fatal("new devices must have no permissions")
	}
	if e = s.SetRule(a.ID, b.ID, true); e != nil {
		t.Fatal(e)
	}
	c, e := s.Config(a.ID, a.Token)
	if e != nil || len(c.Grants) != 1 {
		t.Fatalf("grant not delivered: %v", e)
	}
	back, _ := s.Config(b.ID, b.Token)
	if len(back.Grants) != 0 {
		t.Fatal("single direction grant became mutual")
	}
	left, right := net.Pipe()
	defer right.Close()
	tracked, e := s.Track(left, a.ID, b.ID, runID(a.Token))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SetRule(a.ID, b.ID, false); e != nil {
		t.Fatal(e)
	}
	s.RevokeConnections()
	_ = right.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = right.Read(make([]byte, 1)); e == nil {
		t.Fatal("revoked connection remained open")
	}
	_ = tracked.Close()
	if _, e = s.Track(left, a.ID, b.ID, runID(a.Token)); e == nil {
		t.Fatal("cached credentials bypassed revoked ACL")
	}
	renewed := mustRegister(t, s, "00:11:22:33:44:55", "A")
	if renewed.ID != a.ID || renewed.Token == a.Token {
		t.Fatal("restart identity/session behavior incorrect")
	}
	if _, e = s.Config(a.ID, a.Token); e == nil {
		t.Fatal("old startup session remained valid")
	}
	if e = s.SetEnabled(b.ID, false); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Register(registration("00:11:22:33:44:56", "B")); e != ErrDenied {
		t.Fatal("disabled hardware re-registered")
	}
	reopened, e := OpenStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	ds, _ := reopened.Snapshot()
	for _, d := range ds {
		if d.ID == b.ID && d.Enabled {
			t.Fatal("disable lost across restart")
		}
		if d.Secret != "" {
			t.Fatal("admin snapshot exposed tunnel secret")
		}
	}
	if filepath.Base(reopened.path) != "devices.json" {
		t.Fatal("state missing")
	}
}
func TestAdminAuthenticationCSRFAndSecretRedaction(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	a := mustRegister(t, s, "00:11:22:33:44:55", "<script>A</script>")
	h := AdminHandler(s, "test-password-at-least-16-characters")
	req := httptest.NewRequest("GET", "http://localhost/api/state", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("unauthenticated admin allowed")
	}
	req = httptest.NewRequest("GET", "http://localhost/api/state", nil)
	req.SetBasicAuth("admin", "test-password-at-least-16-characters")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || strings.Contains(w.Body.String(), a.Secret) || strings.Contains(w.Body.String(), a.Token) {
		t.Fatal("snapshot leaked credentials")
	}
	body, _ := json.Marshal(map[string]any{"id": a.ID, "enabled": false})
	req = httptest.NewRequest("POST", "http://localhost/api/devices", bytes.NewReader(body))
	req.SetBasicAuth("admin", "test-password-at-least-16-characters")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://attacker.invalid")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("cross origin mutation accepted")
	}
	ds, _ := s.Snapshot()
	if !ds[0].Enabled {
		t.Fatal("CSRF changed device")
	}
}
func TestRegistrationAPIValidatesFingerprint(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	h := DeviceHandler(s)
	req := httptest.NewRequest("POST", "https://localhost/v1/register", strings.NewReader(`{"fingerprint":{"macs":[]},"name":"bad"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatal("missing MAC accepted")
	}
}

func TestDevicePolicyRejectsImpersonationAndPublicProxy(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	a := mustRegister(t, s, "00:11:22:33:44:55", "A")
	b := mustRegister(t, s, "00:11:22:33:44:56", "B")
	p := &devicePolicy{s}
	res, _, e := p.Handle(context.Background(), plugin.OpLogin, plugin.LoginContent{Login: msg.Login{User: a.ID, Metas: map[string]string{"aissh_session": b.Token}}})
	if e != nil || !res.Reject {
		t.Fatal("another device's session authenticated a claimed identity")
	}
	res, _, e = p.Handle(context.Background(), plugin.OpNewProxy, plugin.NewProxyContent{User: plugin.UserInfo{User: a.ID, Metas: map[string]string{"aissh_session": a.Token}}, NewProxy: msg.NewProxy{ProxyName: a.ID + ".ssh", ProxyType: "tcp", Sk: a.Secret}})
	if e != nil || !res.Reject {
		t.Fatal("device created a public TCP proxy")
	}
	if _, e = s.Track(nil, a.ID, b.ID, ""); e == nil {
		t.Fatal("legacy visitor without a registered session was admitted")
	}
}

func TestOnlineStatusUsesServerHeartbeatAndLiveSession(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := mustRegister(t, s, "00:11:22:33:44:55", "A")
	status := func(want bool) {
		t.Helper()
		devices, _ := s.Snapshot()
		if len(devices) != 1 || devices[0].Online != want {
			t.Fatalf("online = %v, want %v", devices, want)
		}
	}
	status(true)
	// A stale heartbeat must go offline even while the credential remains valid.
	s.mu.Lock()
	s.state.Devices[c.ID].LastSeen = time.Now().Add(-time.Minute)
	s.mu.Unlock()
	status(false)
	if _, err = s.Config(c.ID, c.Token); err != nil {
		t.Fatal(err)
	}
	status(true)
	// A restart discards sessions, so a recent persisted timestamp is insufficient.
	reopened, err := OpenStore(filepath.Dir(s.path))
	if err != nil {
		t.Fatal(err)
	}
	devices, _ := reopened.Snapshot()
	if devices[0].Online {
		t.Fatal("device appeared online without a live session")
	}
	s.mu.Lock()
	session := s.sessions[runID(c.Token)]
	session.Expires = time.Now().Add(-time.Second)
	s.sessions[runID(c.Token)] = session
	s.mu.Unlock()
	status(false)
	c = mustRegister(t, s, "00:11:22:33:44:55", "A")
	status(true)
	if err = s.SetEnabled(c.ID, false); err != nil {
		t.Fatal(err)
	}
	status(false)
}
