package aissh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
)

type AgentOptions struct {
	Host, CAFile, StateDir       string
	APIPort, TunnelPort, SSHPort int
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
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
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
func RunAgent(ctx context.Context, o AgentOptions) error {
	if o.SSHPort < 1 || o.SSHPort > 65535 {
		return fmt.Errorf("invalid local SSH port")
	}
	fp, e := DetectFingerprint()
	if e != nil {
		return fmt.Errorf("identify hardware: %w", e)
	}
	id, _ := fp.ID()
	name, _ := os.Hostname()
	ca, e := TrustPEM(o.CAFile)
	if e != nil {
		return e
	}
	tlsCfg, e := ClientTLS(ca)
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
	h := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	defer h.CloseIdleConnections()
	base := "https://" + o.Host + ":" + strconv.Itoa(o.APIPort)
	log.Printf("device %s (%s); registering with %s", id, name, base)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	var svc *client.Service
	var svcCancel context.CancelFunc
	var svcDone chan struct{}
	var token string
	var lastConfig string
	stopService := func() {
		if svcCancel != nil {
			svcCancel()
		}
		if svcDone != nil {
			<-svcDone
			svcDone = nil
		}
		svc = nil
	}
	defer stopService()
	for {
		var c DeviceConfig
		register := token == ""
		if register {
			e = callAPI(ctx, h, "POST", base+"/v1/register", "", "", Registration{Fingerprint: fp, Name: name, OS: runtime.GOOS}, &c)
		} else {
			e = callAPI(ctx, h, "GET", base+"/v1/config", id, token, nil, &c)
		}
		if e != nil {
			if ae, ok := e.(apiError); ok && (ae.Status == 401 || ae.Status == 403) {
				token = ""
				if svc != nil {
					stopService()
				}
				log.Printf("device registration required or disabled; waiting for administrator")
			} else if ctx.Err() == nil {
				log.Printf("control server unavailable: %v", e)
			}
		} else {
			if c.ID != id {
				return fmt.Errorf("server returned an unexpected device ID")
			}
			if register {
				token = c.Token
				if token == "" {
					return fmt.Errorf("registration returned no session")
				}
				if svc != nil {
					stopService()
				}
				svc, e = newAgentService(o, c, token, caPath)
				if e != nil {
					return e
				}
				svcCancel, svcDone = launchAgentService(ctx, svc)
				log.Printf("registered %s; waiting for access permissions", id)
			}
			p, v := configs(c, o.SSHPort)
			signature, _ := json.Marshal(c.Grants)
			if string(signature) != lastConfig || register {
				if e = svc.UpdateAllConfigurer(p, v); e != nil {
					log.Printf("apply permissions: %v", e)
				} else {
					lastConfig = string(signature)
					for _, g := range c.Grants {
						log.Printf("%s (%s): ssh -p %d USER@127.0.0.1", g.Name, g.Target, g.Port)
					}
				}
			}
			if time.Until(c.Expires) < time.Minute {
				token = ""
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
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
