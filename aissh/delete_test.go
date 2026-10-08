package aissh

import (
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeleteDevice(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := mustRegister(t, s, "00:11:22:33:44:51", "A")
	b := mustRegister(t, s, "00:11:22:33:44:52", "B")
	c := mustRegister(t, s, "00:11:22:33:44:53", "C")
	for _, pair := range [][2]string{{a.ID, b.ID}, {b.ID, a.ID}, {a.ID, c.ID}} {
		if err := s.SetRule(pair[0], pair[1], true); err != nil {
			t.Fatal(err)
		}
	}
	left, right := net.Pipe()
	defer right.Close()
	tracked, err := s.Track(left, a.ID, b.ID, runID(a.Token))
	if err != nil {
		t.Fatal(err)
	}
	defer tracked.Close()
	if err := s.DeleteDevice(b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Config(b.ID, b.Token); err != ErrDenied {
		t.Fatalf("deleted session: %v", err)
	}
	right.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := right.Read(make([]byte, 1)); err == nil {
		t.Fatal("deleted tunnel still open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("deleted tunnel was not closed")
	}
	if _, err := s.Track(left, a.ID, b.ID, runID(a.Token)); err != ErrDenied {
		t.Fatalf("deleted target allowed: %v", err)
	}
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ds, rs := reopened.Snapshot()
	if len(ds) != 2 || len(rs) != 1 || rs[0].Target != c.ID || rs[0].Port != 22001 {
		t.Fatalf("unexpected persisted devices/rules: %v %v", ds, rs)
	}
	fresh := mustRegister(t, s, "00:11:22:33:44:52", "B")
	if fresh.ID != b.ID || len(fresh.Grants) != 0 || fresh.Secret == b.Secret {
		t.Fatal("re-registration reused permissions or secret")
	}
	cfg, err := s.Config(a.ID, a.Token)
	if err != nil || len(cfg.Grants) != 1 || cfg.Grants[0].Target != c.ID {
		t.Fatalf("unrelated permissions changed: %v", err)
	}
	if err := s.DeleteDevice("unknown"); err == nil {
		t.Fatal("unknown deletion accepted")
	}
}

func TestDeleteDeviceSaveFailure(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	a := mustRegister(t, s, "00:11:22:33:44:51", "A")
	b := mustRegister(t, s, "00:11:22:33:44:52", "B")
	if err := s.SetRule(a.ID, b.ID, true); err != nil {
		t.Fatal(err)
	}
	s.path = filepath.Join(t.TempDir(), "missing", "devices.json")
	if err := s.DeleteDevice(b.ID); err == nil {
		t.Fatal("save failure ignored")
	}
	if _, err := s.Config(b.ID, b.Token); err != nil {
		t.Fatal("session lost on save failure")
	}
	_, rs := s.Snapshot()
	if len(rs) != 1 {
		t.Fatal("rules lost on save failure")
	}
}

func TestAdminDeleteDevice(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	d := mustRegister(t, s, "00:11:22:33:44:51", "A")
	h := AdminHandler(s, "test-password")
	for _, tc := range []struct {
		auth   bool
		origin string
		status int
	}{{false, "", 401}, {true, "https://evil.example", 403}, {true, "http://example.com", 200}} {
		r := httptest.NewRequest("POST", "http://example.com/api/devices/delete", strings.NewReader(`{"id":"`+d.ID+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", tc.origin)
		if tc.auth {
			r.SetBasicAuth("admin", "test-password")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("got %d want %d: %s", w.Code, tc.status, w.Body.String())
		}
	}
	ds, _ := s.Snapshot()
	if len(ds) != 0 {
		t.Fatal("admin deletion did not remove device")
	}
}
