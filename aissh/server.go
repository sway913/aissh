package aissh

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/server"
)

type ServerOptions struct {
	DataDir, APIAddr, AdminAddr string
	TunnelPort                  int
}

func RunServer(ctx context.Context, o ServerOptions) error {
	s, e := OpenStore(o.DataDir)
	if e != nil {
		return e
	}
	cert, key := filepath.Join(o.DataDir, "server.crt"), filepath.Join(o.DataDir, "server.key")
	if _, e = os.Stat(cert); e != nil {
		return fmt.Errorf("initialize server TLS with --init-tls first: %w", e)
	}
	passwordPath := filepath.Join(o.DataDir, "admin-password")
	password, e := os.ReadFile(passwordPath)
	if os.IsNotExist(e) {
		password = []byte(randomSecret())
		e = os.WriteFile(passwordPath, password, 0600)
	}
	if e != nil {
		return e
	}
	if len(strings.TrimSpace(string(password))) < 16 {
		return fmt.Errorf("admin password too short")
	}
	cfg := &v1.ServerConfig{BindAddr: "0.0.0.0", BindPort: o.TunnelPort}
	cfg.Transport.TLS.CertFile = cert
	cfg.Transport.TLS.KeyFile = key
	cfg.Transport.TLS.Force = true
	if e = cfg.Complete(); e != nil {
		return e
	}
	svr, e := server.NewService(cfg)
	if e != nil {
		return e
	}
	defer svr.Close()
	svr.RegisterPlugin(&devicePolicy{store: s})
	svr.SetVisitorConnHook(func(c net.Conn, user, rid, proxy string) (net.Conn, error) {
		return s.Track(c, user, targetFromProxy(proxy), rid)
	})
	api := &http.Server{Addr: o.APIAddr, Handler: DeviceHandler(s), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	admin := &http.Server{Addr: o.AdminAddr, Handler: AdminHandler(s, strings.TrimSpace(string(password))), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	apiLn, e := net.Listen("tcp", o.APIAddr)
	if e != nil {
		return e
	}
	defer apiLn.Close()
	adminLn, e := net.Listen("tcp", o.AdminAddr)
	if e != nil {
		return e
	}
	defer adminLn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 3)
	go func() { errs <- api.ServeTLS(apiLn, cert, key) }()
	go func() { errs <- admin.Serve(adminLn) }()
	go func() { svr.Run(ctx); errs <- nil }()
	log.Printf("aissh registration API: https://%s; admin: http://%s (admin password file: %s)", o.APIAddr, o.AdminAddr, passwordPath)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var result error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case e := <-errs:
			if e != nil && !errors.Is(e, http.ErrServerClosed) {
				result = e
			}
			break loop
		case <-ticker.C:
			s.RevokeConnections()
		}
	}
	cancel()
	_ = api.Close()
	_ = admin.Close()
	return result
}
