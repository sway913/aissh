package visitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/naming"
	"github.com/fatedier/frp/pkg/util/util"
)

// ErrAccessDenied is a terminal admission failure, never a failover signal.
var ErrAccessDenied = errors.New("aissh authorization denied")

// DialSTCP opens a visitor stream without owning a local listening port.
// The caller owns the returned connection and must not enable stream transforms.
func (vm *Manager) DialSTCP(ctx context.Context, name string) (net.Conn, error) {
	vm.mu.RLock()
	cfg, ok := vm.cfgs[name]
	helper, common := vm.helper, vm.clientCfg
	vm.mu.RUnlock()
	if !ok || cfg.GetBaseConfig().Type != "stcp" {
		return nil, fmt.Errorf("visitor %s unavailable", name)
	}
	c := *cfg.GetBaseConfig()
	if c.Transport.UseEncryption || c.Transport.UseCompression {
		return nil, fmt.Errorf("direct STCP dial requires TLS without stream transforms")
	}
	type result struct {
		conn *msg.Conn
		err  error
	}
	ready := make(chan result)
	go func() {
		conn, err := helper.ConnectServer()
		select {
		case ready <- result{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	var conn *msg.Conn
	select {
	case r := <-ready:
		if r.err != nil {
			return nil, r.err
		}
		conn = r.conn
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	now := time.Now().Unix()
	request := &msg.NewVisitorConn{RunID: helper.RunID(), ProxyName: naming.BuildTargetServerProxyName(common.User, c.ServerUser, c.ServerName), SignKey: util.GetAuthKey(c.SecretKey, now), Timestamp: now}
	err := conn.WriteMsg(request)
	var response msg.NewVisitorConnResp
	if err == nil {
		err = conn.ReadMsgInto(&response)
	}
	if err == nil && response.Error != "" {
		if response.Error == ErrAccessDenied.Error() {
			err = ErrAccessDenied
		} else {
			err = fmt.Errorf("visitor: %s", response.Error)
		}
	}
	if err != nil || ctx.Err() != nil {
		_ = conn.Close()
		if err == nil {
			err = ctx.Err()
		}
		return nil, err
	}
	if !stop() || ctx.Err() != nil {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
