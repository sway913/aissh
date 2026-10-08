package server

import (
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"net"
)

// RegisterPlugin installs an in-process policy plugin before Run is called.
func (svr *Service) RegisterPlugin(p plugin.Plugin) { svr.pluginManager.Register(p) }

// SetVisitorConnHook adds an admission policy without changing the frp wire protocol.
// Set before Run. The callback must not call back into the control manager.
// The hook may wrap conn to track its lifetime and revoke active connections.
func (svr *Service) SetVisitorConnHook(hook func(conn net.Conn, user, runID, proxyName string) (net.Conn, error)) {
	svr.visitorConnHook = hook
}
