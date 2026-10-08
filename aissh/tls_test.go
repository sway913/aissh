package aissh

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDomainServerTLSVerification(t *testing.T) {
	if net.ParseIP(DefaultHost) != nil {
		t.Fatal("default server must be a DNS name")
	}
	dir := t.TempDir()
	if err := InitTLS(dir, DefaultHost); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := ClientTLS(ca)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: config, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("https://" + DefaultHost + "/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal(response.StatusCode)
	}
	if _, err = client.Get("https://149.88.87.82/"); err == nil {
		t.Fatal("old public IP unexpectedly accepted by domain certificate")
	}
	if _, err = client.Get("https://wrong.example/"); err == nil {
		t.Fatal("wrong hostname accepted")
	}
}
