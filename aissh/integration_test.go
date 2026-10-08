package aissh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/server"
	"golang.org/x/crypto/ssh"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}
func sshBackend(t *testing.T) int {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(key)
	if e != nil {
		t.Fatal(e)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				conn, channels, requests, e := ssh.NewServerConn(c, cfg)
				if e != nil {
					_ = c.Close()
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					ch, reqs, e := incoming.Accept()
					if e != nil {
						continue
					}
					go func() {
						defer ch.Close()
						for r := range reqs {
							if r.Type == "exec" {
								_ = r.Reply(true, nil)
								_, _ = io.WriteString(ch, "computer-b\n")
								_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								return
							}
							_ = r.Reply(false, nil)
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}
func dialSSH(port int) (*ssh.Client, error) {
	c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 300*time.Millisecond)
	if e != nil {
		return nil, e
	}
	_ = c.SetDeadline(time.Now().Add(time.Second))
	cc, ch, reqs, e := ssh.NewClientConn(c, "test", &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if e != nil {
		_ = c.Close()
		return nil, e
	}
	_ = c.SetDeadline(time.Time{})
	return ssh.NewClient(cc, ch, reqs), nil
}
func waitSSH(t *testing.T, port int) *ssh.Client {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, e := dialSSH(port)
		if e == nil {
			return c
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("SSH tunnel never became ready")
	return nil
}
func TestSSHAuthorizationAndCachedCredentialRevocation(t *testing.T) {
	dir := t.TempDir()
	if e := InitTLS(dir, "127.0.0.1"); e != nil {
		t.Fatal(e)
	}
	store, _ := OpenStore(dir)
	a := mustRegister(t, store, "00:11:22:33:44:55", "A")
	b := mustRegister(t, store, "00:11:22:33:44:56", "B")
	c := mustRegister(t, store, "00:11:22:33:44:57", "C")
	if e := store.SetRule(a.ID, b.ID, true); e != nil {
		t.Fatal(e)
	}
	// Assign ephemeral visitor ports to avoid collisions on developer machines.
	store.mu.Lock()
	store.state.Rules[0].Port = freePort(t)
	store.mu.Unlock()
	ac, _ := store.Config(a.ID, a.Token)
	bc, _ := store.Config(b.ID, b.Token)
	tunnelPort := freePort(t)
	cfg := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: tunnelPort}
	cfg.Transport.TLS.CertFile = filepath.Join(dir, "server.crt")
	cfg.Transport.TLS.KeyFile = filepath.Join(dir, "server.key")
	cfg.Transport.TLS.Force = true
	if e := cfg.Complete(); e != nil {
		t.Fatal(e)
	}
	svr, e := server.NewService(cfg)
	if e != nil {
		t.Fatal(e)
	}
	svr.RegisterPlugin(&devicePolicy{store})
	svr.SetVisitorConnHook(func(n net.Conn, user, rid, proxy string) (net.Conn, error) {
		return store.Track(n, user, targetFromProxy(proxy), rid)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer svr.Close()
	go svr.Run(ctx)
	backend := sshBackend(t)
	start := func(conf DeviceConfig, token string) {
		t.Helper()
		s, e := newAgentService(AgentOptions{Host: "127.0.0.1", TunnelPort: tunnelPort, SSHPort: backend}, conf, token, filepath.Join(dir, "server.crt"))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(s.Close)
		go func() { _ = s.Run(ctx) }()
	}
	start(bc, b.Token)
	start(ac, a.Token)
	cli := waitSSH(t, ac.Grants[0].Port)
	defer cli.Close()
	sess, e := cli.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	out, e := sess.CombinedOutput("hostname")
	if e != nil || string(out) != "computer-b\n" {
		t.Fatalf("SSH exec through TLS/STCP failed: %q %v", out, e)
	}
	_ = sess.Close()
	// C knows B's STCP secret but has no ACL grant. The server must still reject it.
	cc, _ := store.Config(c.ID, c.Token)
	unauthorizedPort := freePort(t)
	cc.Grants = []Grant{{Target: b.ID, Name: "B", Port: unauthorizedPort, Secret: b.Secret}}
	start(cc, c.Token)
	time.Sleep(300 * time.Millisecond)
	if unauthorized, e := dialSSH(unauthorizedPort); e == nil {
		_ = unauthorized.Close()
		t.Fatal("unauthorized C connected with copied STCP secret")
	}
	if e := store.SetRule(a.ID, b.ID, false); e != nil {
		t.Fatal(e)
	}
	store.RevokeConnections()
	// A's client deliberately keeps its old visitor config and cached secret.
	if _, e = cli.NewSession(); e == nil {
		t.Fatal("revocation did not close existing SSH transport")
	}
	if reconnect, e := dialSSH(ac.Grants[0].Port); e == nil {
		_ = reconnect.Close()
		t.Fatal("cached credentials bypassed server ACL")
	}
	t.Log(fmt.Sprintf("SSH exec, directed ACL, unauthorized-device rejection, and active/cached revocation verified on port %d", tunnelPort))
}
