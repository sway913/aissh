package client

import (
	"context"
	"fmt"
	"net"
)

// DialSTCP reuses the authenticated control session without binding a TCP port.
func (svr *Service) DialSTCP(ctx context.Context, name string) (net.Conn, error) {
	svr.ctlMu.RLock()
	ctl := svr.ctl
	svr.ctlMu.RUnlock()
	if ctl == nil {
		return nil, fmt.Errorf("tunnel not connected")
	}
	return ctl.vm.DialSTCP(ctx, name)
}
