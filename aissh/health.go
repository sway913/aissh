package aissh

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func CheckServerHealth(dir, addr string) error {
	ca, err := os.ReadFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		return err
	}
	tlsConfig, err := ClientTLS(ca)
	if err != nil {
		return err
	}
	tlsConfig.ServerName = "localhost"
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	h := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	defer h.CloseIdleConnections()
	res, err := h.Get("https://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("node unhealthy: HTTP %d", res.StatusCode)
	}
	return nil
}
