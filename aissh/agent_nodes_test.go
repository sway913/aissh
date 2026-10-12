package aissh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/client/visitor"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/server"
)

func TestSSHProbePreservesBannerAndBoundsWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	go func() { io.WriteString(b, "notice\r\nSSH-2.0-test\r\nremaining") }()
	conn, reader, banner, err := probeSSH(ctx, func(context.Context) (net.Conn, error) { return a, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if string(banner) != "notice\r\nSSH-2.0-test\r\n" {
		t.Fatalf("lost identification: %q", banner)
	}
	data := make([]byte, 9)
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "remaining" {
		t.Fatalf("lost buffered bytes: %q %v", data, err)
	}
	a2, b2 := net.Pipe()
	defer b2.Close()
	short, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	if _, _, _, err := probeSSH(short, func(context.Context) (net.Conn, error) { return a2, nil }); err == nil {
		t.Fatal("silent endpoint never timed out")
	}
	if _, _, _, err := probeSSH(ctx, func(context.Context) (net.Conn, error) { return nil, visitor.ErrAccessDenied }); !errors.Is(err, visitor.ErrAccessDenied) {
		t.Fatal("terminal denial lost")
	}
}
func TestDualNodeRoutePriorityFallbackAndDenial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authority, _ := OpenStore(t.TempDir())
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	authority.signingKey = priv
	a := mustRegister(t, authority, "00:11:22:33:44:55", "A")
	b := mustRegister(t, authority, "00:11:22:33:44:56", "B")
	authority.SetRule(a.ID, b.ID, true)
	port := freePort(t)
	authority.state.Rules[0].Port = port
	replica, _ := OpenStore(t.TempDir())
	replica.replica = true
	replica.federation = &FederationConfig{PublicKey: base64.StdEncoding.EncodeToString(pub)}
	signed, _ := authority.signedSnapshot()
	if err := replica.applyPolicy(signed, false); err != nil {
		t.Fatal(err)
	}
	backend := sshBackend(t)
	var lanHits, publicHits atomic.Int32
	type nodeInstance struct {
		worker *nodeWorker
		target *client.Service
		server *server.Service
		store  *Store
		source DeviceConfig
		revive func()
	}
	start := func(id, kind string, store *Store, hits *atomic.Int32) nodeInstance {
		dir := t.TempDir()
		InitTLS(dir, "127.0.0.1")
		cfg := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: freePort(t)}
		cfg.Transport.TLS.CertFile = filepath.Join(dir, "server.crt")
		cfg.Transport.TLS.KeyFile = filepath.Join(dir, "server.key")
		cfg.Transport.TLS.Force = true
		cfg.Complete()
		svr, err := server.NewService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { svr.Close() })
		svr.RegisterPlugin(&devicePolicy{store})
		svr.SetVisitorConnHook(func(c net.Conn, user, rid, proxy string) (net.Conn, error) {
			hits.Add(1)
			wrapped, err := store.Track(c, user, targetFromProxy(proxy), rid)
			if err != nil {
				return nil, server.ErrVisitorDenied
			}
			return wrapped, nil
		})
		go svr.Run(ctx)
		ac, err := store.Register(registration("00:11:22:33:44:55", "A"))
		if err != nil {
			t.Fatal(err)
		}
		bc, err := store.Register(registration("00:11:22:33:44:56", "B"))
		if err != nil {
			t.Fatal(err)
		}
		o := AgentOptions{Host: "127.0.0.1", TunnelPort: cfg.BindPort, SSHPort: backend}
		source, err := newAgentService(o, hiddenPortConfig(ac), ac.Token, cfg.Transport.TLS.CertFile)
		if err != nil {
			t.Fatal(err)
		}
		target, err := newAgentService(o, hiddenPortConfig(bc), bc.Token, cfg.Transport.TLS.CertFile)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(source.Close)
		t.Cleanup(target.Close)
		go source.Run(ctx)
		go target.Run(ctx)
		revive := func() {
			fresh, err := store.Register(registration("00:11:22:33:44:56", "B"))
			if err != nil {
				t.Fatal(err)
			}
			replacement, err := newAgentService(o, hiddenPortConfig(fresh), fresh.Token, cfg.Transport.TLS.CertFile)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(replacement.Close)
			go replacement.Run(ctx)
		}
		return nodeInstance{&nodeWorker{node: Node{ID: id, Kind: kind}, svc: source, grants: map[string]bool{b.ID: true}, expires: ac.Expires, cancel: func() {}}, target, svr, store, ac, revive}
	}
	lan := start("lan", "lan", replica, &lanHits)
	hk := start("hongkong", "public", authority, &publicHits)
	r := &agentRouter{ctx: ctx, workers: map[string]*nodeWorker{"lan": lan.worker, "hongkong": hk.worker}, listeners: map[int]routeListener{}, active: map[net.Conn]string{}, grants: map[string]Grant{}}
	defer r.shutdown()
	r.applyConfig(hk.source, true)
	execute := func() {
		t.Helper()
		cli := waitSSH(t, port)
		defer cli.Close()
		s, err := cli.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		out, err := s.CombinedOutput("hostname")
		s.Close()
		if err != nil || string(out) != "computer-b\n" {
			t.Fatalf("exec: %q %v", out, err)
		}
	}
	// Wait for both independent proxies before measuring route choice.
	deadline := time.Now().Add(5 * time.Second)
	for !lan.server.HasProxy(b.ID+".ssh") || !hk.server.HasProxy(b.ID+".ssh") {
		if time.Now().After(deadline) {
			t.Fatal("proxies not ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	execute()
	if lanHits.Load() == 0 || publicHits.Load() != 0 {
		t.Fatalf("LAN not preferred: %d/%d", lanHits.Load(), publicHits.Load())
	}
	// Target has only the public route; the local port remains unchanged.
	lan.target.Close()
	time.Sleep(100 * time.Millisecond)
	execute()
	if publicHits.Load() == 0 {
		t.Fatal("public fallback not used")
	}
	// A connected LAN node explicitly rejects this permission. Never retry public.
	replica.mu.Lock()
	replica.state.Rules = nil
	replica.mu.Unlock()
	before := publicHits.Load()
	if cli, err := dialSSH(port); err == nil {
		cli.Close()
		t.Fatal("ACL denial bypassed through fallback")
	}
	if publicHits.Load() != before {
		t.Fatal("explicit denial retried public route")
	}
	replica.mu.Lock()
	replica.state.Rules = []Rule{{Source: a.ID, Target: b.ID, Port: port}}
	replica.mu.Unlock()
	lan.revive()
	deadline = time.Now().Add(5 * time.Second)
	for !lan.server.HasProxy(b.ID + ".ssh") {
		if time.Now().After(deadline) {
			t.Fatal("LAN proxy did not recover")
		}
		time.Sleep(20 * time.Millisecond)
	}
	oldLAN, oldPublic := lanHits.Load(), publicHits.Load()
	execute()
	if lanHits.Load() <= oldLAN || publicHits.Load() != oldPublic {
		t.Fatal("recovered LAN was not preferred")
	}
	hk.server.Close()
	execute()
	r.mu.Lock()
	r.clearLocked()
	r.mu.Unlock()
	if len(r.listeners) != 0 {
		t.Fatal("listeners survived authorization expiry")
	}
}
