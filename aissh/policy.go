package aissh

import (
	"context"
	"fmt"
	"strings"

	plugin "github.com/fatedier/frp/pkg/plugin/server"
)

type devicePolicy struct{ store *Store }

func (p *devicePolicy) Name() string { return "aissh-device-policy" }
func (p *devicePolicy) IsSupport(op string) bool {
	return op == plugin.OpLogin || op == plugin.OpNewProxy || op == plugin.OpPing || op == plugin.OpNewWorkConn
}
func (p *devicePolicy) Handle(_ context.Context, op string, content any) (*plugin.Response, any, error) {
	s := p.store
	s.mu.Lock()
	defer s.mu.Unlock()
	reject := func() (*plugin.Response, any, error) {
		return &plugin.Response{Reject: true, RejectReason: "aissh authorization denied"}, nil, nil
	}
	switch op {
	case plugin.OpLogin:
		c := content.(plugin.LoginContent)
		v, e := s.sessionLocked(c.User, c.Metas["aissh_session"])
		if e != nil {
			return reject()
		}
		c.RunID = runID(v.Token)
		c.ClientID = c.User
		return &plugin.Response{Unchange: false}, &c, nil
	case plugin.OpNewProxy:
		c := content.(plugin.NewProxyContent)
		_, e := s.sessionLocked(c.User.User, c.User.Metas["aissh_session"])
		d := s.state.Devices[c.User.User]
		if e != nil || d == nil || c.ProxyType != "stcp" || c.ProxyName != c.User.User+".ssh" || c.Sk != d.Secret {
			return reject()
		}
		c.AllowUsers = []string{"*"}
		return &plugin.Response{Unchange: false}, &c, nil
	case plugin.OpPing:
		c := content.(plugin.PingContent)
		if _, e := s.sessionLocked(c.User.User, c.User.Metas["aissh_session"]); e != nil {
			return reject()
		}
	case plugin.OpNewWorkConn:
		c := content.(plugin.NewWorkConnContent)
		v, e := s.sessionLocked(c.User.User, c.User.Metas["aissh_session"])
		if e != nil || c.RunID != runID(v.Token) {
			return reject()
		}
	default:
		return nil, nil, fmt.Errorf("unsupported policy operation")
	}
	return &plugin.Response{Unchange: true}, content, nil
}
func targetFromProxy(name string) string {
	if !strings.HasSuffix(name, ".ssh") {
		return ""
	}
	return strings.TrimSuffix(name, ".ssh")
}
