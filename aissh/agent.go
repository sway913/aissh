package aissh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
)

type AgentOptions struct {
	Host, APIURL, CAFile, StateDir string
	TunnelPort, SSHPort            int
	ManagedIdentity                *StartupConfig `json:"-"`
}
type apiError struct{ Status int }

func (e apiError) Error() string { return fmt.Sprintf("server returned HTTP %d", e.Status) }
func callAPI(ctx context.Context, h *http.Client, method, url, id, token string, body any, out any) error {
	var b []byte
	var e error
	if body != nil {
		b, e = json.Marshal(body)
		if e != nil {
			return e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Aissh-Device", id)
	}
	res, e := h.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return apiError{res.StatusCode}
	}
	return json.NewDecoder(io.LimitReader(res.Body, 32<<20)).Decode(out)
}
func configs(c DeviceConfig, sshPort int) ([]v1.ProxyConfigurer, []v1.VisitorConfigurer) {
	p := &v1.STCPProxyConfig{ProxyBaseConfig: v1.ProxyBaseConfig{Name: "ssh", Type: "stcp", ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: sshPort}}, Secretkey: c.Secret, AllowUsers: []string{"*"}}
	p.Complete()
	visitors := make([]v1.VisitorConfigurer, 0, len(c.Grants))
	for _, g := range c.Grants {
		v := &v1.STCPVisitorConfig{VisitorBaseConfig: v1.VisitorBaseConfig{Name: "to-" + g.Target, Type: "stcp", ServerUser: g.Target, ServerName: "ssh", SecretKey: g.Secret, BindAddr: "127.0.0.1", BindPort: g.Port}}
		v.Complete()
		visitors = append(visitors, v)
	}
	return []v1.ProxyConfigurer{p}, visitors
}
func newAgentService(o AgentOptions, c DeviceConfig, token, caPath string) (*client.Service, error) {
	common := &v1.ClientCommonConfig{ServerAddr: o.Host, ServerPort: o.TunnelPort, User: c.ID, ClientID: c.ID, Metadatas: map[string]string{"aissh_session": token}}
	common.Transport.TLS.TrustedCaFile = caPath
	common.Transport.TLS.ServerName = o.Host
	common.Transport.Protocol = "tcp"
	exit := false
	common.LoginFailExit = &exit
	common.Transport.HeartbeatInterval = 10
	common.Transport.HeartbeatTimeout = 30
	if e := common.Complete(); e != nil {
		return nil, e
	}
	p, v := configs(c, o.SSHPort)
	cs := source.NewConfigSource()
	if e := cs.ReplaceAll(p, v); e != nil {
		return nil, e
	}
	return client.NewService(client.ServiceOptions{Common: common, ConfigSourceAggregator: source.NewAggregator(cs)})
}
func registrationURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("registration URL must be an HTTPS origin without credentials, path, query or fragment")
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

func registrationClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func RunAgent(ctx context.Context, o AgentOptions) error {
	base, e := registrationURL(o.APIURL)
	if e != nil {
		return e
	}
	if o.SSHPort < 1 || o.SSHPort > 65535 {
		return fmt.Errorf("invalid local SSH port")
	}
	fp, e := DetectFingerprint()
	if e != nil {
		return fmt.Errorf("identify hardware: %w", e)
	}
	if o.ManagedIdentity != nil && runtime.GOOS == "windows" {
		fp.Hardware = o.ManagedIdentity.Hardware
	}
	id, _ := fp.ID()
	name, _ := os.Hostname()
	username, account, accountErr := detectAccount(runtime.GOOS, name)
	if o.ManagedIdentity != nil && runtime.GOOS == "windows" {
		username, account, accountErr = o.ManagedIdentity.Username, o.ManagedIdentity.Account, nil
	}
	if accountErr != nil {
		log.Printf("unable to read system account: %v", accountErr)
	} else {
		log.Printf("system account %s; SSH username %s", account, username)
	}
	ca, e := TrustPEM(o.CAFile)
	if e != nil {
		return e
	}
	_, e = ClientTLS(ca)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(o.StateDir, 0700); e != nil {
		return e
	}
	caPath := filepath.Join(o.StateDir, "server-ca.pem")
	if e = os.WriteFile(caPath, ca, 0600); e != nil {
		return e
	}
	log.Printf("device %s (%s); registering with %s", id, name, base)
	return runMultiNodeAgent(ctx, o, Registration{Fingerprint: fp, Name: name, OS: runtime.GOOS, Username: username, Account: account}, id, ca)
}

func launchAgentService(ctx context.Context, svc *client.Service) (context.CancelFunc, chan struct{}) {
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		if err := svc.Run(runCtx); err != nil && runCtx.Err() == nil {
			log.Printf("tunnel stopped: %v", err)
		}
	}()
	return cancel, done
}
