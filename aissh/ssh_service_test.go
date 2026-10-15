package aissh

import (
	"context"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSSHServiceProbe(t *testing.T) {
	for _, tc := range []struct{ banner, state string }{{"SSH-2.0-OpenSSH_test\r\n", "ready"}, {"HTTP/1.1 200 OK\r\n", "unavailable"}, {strings.Repeat("x", 9000), "unavailable"}} {
		t.Run(tc.state+strconv.Itoa(len(tc.banner)), func(t *testing.T) {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			go func() {
				c, e := l.Accept()
				if e == nil {
					defer c.Close()
					c.Write([]byte(tc.banner))
				}
			}()
			got := probeSSHService(l.Addr().(*net.TCPAddr).Port)
			if got.State != tc.state {
				t.Fatalf("got %+v", got)
			}
		})
	}
}
func TestSSHRepairPlatforms(t *testing.T) {
	for _, manager := range []string{"apt-get", "dnf", "yum", "zypper", "apk"} {
		t.Run(manager, func(t *testing.T) {
			look := func(n string) (string, error) {
				if n == manager || n == "systemctl" {
					return n, nil
				}
				return "", net.ErrClosed
			}
			cmds, e := sshRepairCommands("linux", look)
			if e != nil {
				t.Fatal(e)
			}
			if cmds[0][0] != manager || cmds[len(cmds)-1][0] != "sh" {
				t.Fatal(cmds)
			}
		})
	}
	for _, platform := range []string{"windows", "darwin"} {
		if c, e := sshRepairCommands(platform, nil); e != nil || len(c) == 0 {
			t.Fatal(platform, c, e)
		}
	}
	if _, e := sshRepairCommands("linux", func(string) (string, error) { return "", net.ErrClosed }); e == nil {
		t.Fatal("unsupported package manager accepted")
	}
}

func TestSSHStatusAuthenticatedHeartbeat(t *testing.T) {
	s, e := OpenStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	c := mustRegister(t, s, "00:11:22:33:44:55", "test")
	h := httptest.NewServer(DeviceHandler(s))
	defer h.Close()
	status := SSHServiceStatus{State: "ready", Detail: "SSH 就绪", CheckedAt: time.Now().Add(24 * time.Hour)}
	var out DeviceConfig
	if e := callAPI(context.Background(), h.Client(), "GET", h.URL+"/v1/config", c.ID, "invalid", status, &out); e == nil {
		t.Fatal("unauthenticated heartbeat accepted")
	}
	if s.state.Devices[c.ID].SSHService.State != "" {
		t.Fatal("unauthenticated status stored")
	}
	if e := callAPI(context.Background(), h.Client(), "GET", h.URL+"/v1/config", c.ID, c.Token, status, &out); e != nil {
		t.Fatal(e)
	}
	got := s.state.Devices[c.ID].SSHService
	if got.State != "ready" || got.CheckedAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("invalid stored status %+v", got)
	}
	s.recordSSHStatus(c.ID, c.Token, SSHServiceStatus{State: "bogus"})
	if s.state.Devices[c.ID].SSHService.State != "ready" {
		t.Fatal("invalid enum stored")
	}
	if e := callAPI(context.Background(), h.Client(), "GET", h.URL+"/v1/config", c.ID, c.Token, nil, &out); e != nil {
		t.Fatal("old client heartbeat broken", e)
	}
}

func TestSSHStatusFreshnessUsesServerClock(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately differ from the wall clock/browser time by several hours.
	now := time.Now().Add(-3 * time.Hour)
	s.clock = func() time.Time { return now }
	c := mustRegister(t, s, "00:11:22:33:44:55", "clock-test")
	s.recordSSHStatus(c.ID, c.Token, SSHServiceStatus{State: "ready", CheckedAt: time.Now()})
	devices, _ := s.Snapshot()
	if !devices[0].SSHService.Fresh {
		t.Fatal("fresh report rejected because of a different clock")
	}
	now = now.Add(46 * time.Second)
	devices, _ = s.Snapshot()
	if devices[0].SSHService.Fresh {
		t.Fatal("stale SSH report remained fresh")
	}
	// A sender cannot manufacture freshness using its own boolean or timestamp.
	s.recordSSHStatus(c.ID, "invalid", SSHServiceStatus{State: "ready", Fresh: true, CheckedAt: now})
	devices, _ = s.Snapshot()
	if devices[0].SSHService.Fresh {
		t.Fatal("unauthenticated report refreshed status")
	}
}
