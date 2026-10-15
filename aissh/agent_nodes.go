package aissh

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/client/visitor"
)

type nodeWorker struct {
	node    Node
	cancel  context.CancelFunc
	svc     *client.Service // protected by agentRouter.mu
	grants  map[string]bool
	expires time.Time
}
type routeListener struct {
	net.Listener
	target string
}
type agentRouter struct {
	mu              sync.Mutex
	ctx             context.Context
	options         AgentOptions
	identity        *DeviceIdentity
	registration    Registration
	id              string
	ca              []byte
	workers         map[string]*nodeWorker
	listeners       map[int]routeListener
	active          map[net.Conn]string
	grants          map[string]Grant
	revision        uint64
	issued, expires time.Time
	blocked         bool
	closed          bool
	workersDone     sync.WaitGroup
}
type nodeCache struct {
	Authority string `json:"authority"`
	Nodes     []Node `json:"nodes"`
}

func runMultiNodeAgent(ctx context.Context, o AgentOptions, registration Registration, id string, ca []byte) error {
	return runMultiNodeAgentWithIdentity(ctx, o, registration, &DeviceIdentity{ID: id}, ca)
}
func runMultiNodeAgentWithIdentity(ctx context.Context, o AgentOptions, registration Registration, identity *DeviceIdentity, ca []byte) error {
	id := identity.ID
	r := &agentRouter{identity: identity, ctx: ctx, options: o, registration: registration, id: id, ca: ca, workers: map[string]*nodeWorker{}, listeners: map[int]routeListener{}, active: map[net.Conn]string{}, grants: map[string]Grant{}}
	nodes := []Node{{ID: "hongkong", Label: "香港", Kind: "public", APIURL: o.APIURL, Host: o.Host, TunnelPort: o.TunnelPort, Priority: 100, CAPEM: string(ca)}}
	if b, err := os.ReadFile(filepath.Join(o.StateDir, "nodes.json")); err == nil {
		var cache nodeCache
		if json.Unmarshal(b, &cache) == nil && cache.Authority == o.APIURL && len(cache.Nodes) > 0 && validNodes(cache.Nodes) == nil {
			nodes = cache.Nodes
		}
	}
	r.discover(nodes)
	defer r.shutdown()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.mu.Lock()
			if !r.expires.IsZero() && !time.Now().Before(r.expires) {
				r.clearLocked()
			}
			r.mu.Unlock()
		}
	}
}
func (r *agentRouter) shutdown() {
	r.mu.Lock()
	r.closed = true
	for _, w := range r.workers {
		w.cancel()
	}
	r.clearLocked()
	r.mu.Unlock()
	r.workersDone.Wait()
}
func (r *agentRouter) clearLocked() {
	for port, l := range r.listeners {
		l.Close()
		delete(r.listeners, port)
	}
	for c := range r.active {
		c.Close()
		delete(r.active, c)
	}
	r.grants = map[string]Grant{}
}
func (r *agentRouter) discover(nodes []Node) {
	if len(nodes) == 0 || validNodes(nodes) != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil {
		return
	}
	keep := map[string]bool{}
	for _, n := range nodes {
		keep[n.ID] = true
		if old := r.workers[n.ID]; old != nil {
			if old.node == n {
				continue
			}
			old.cancel()
		}
		ctx, cancel := context.WithCancel(r.ctx)
		w := &nodeWorker{node: n, cancel: cancel, grants: map[string]bool{}}
		r.workers[n.ID] = w
		r.workersDone.Add(1)
		go func() { defer r.workersDone.Done(); r.runNode(ctx, w) }()
	}
	for id, w := range r.workers {
		if !keep[id] {
			w.cancel()
			delete(r.workers, id)
		}
	}
	b, _ := json.Marshal(nodeCache{Authority: r.options.APIURL, Nodes: nodes})
	if err := atomicPrivate(filepath.Join(r.options.StateDir, "nodes.json"), b); err != nil {
		log.Printf("cache node discovery: %v", err)
	}
}
func hiddenPortConfig(c DeviceConfig) DeviceConfig {
	c.Grants = append([]Grant(nil), c.Grants...)
	for i := range c.Grants {
		c.Grants[i].Port = -1
	}
	return c
}
func (r *agentRouter) runNode(ctx context.Context, w *nodeWorker) {
	n := w.node
	ca := r.ca
	if n.CAPEM != "" {
		ca = []byte(n.CAPEM)
	}
	// Use a generated filename; node IDs are metadata, never filesystem paths.
	f, err := os.CreateTemp(r.options.StateDir, "node-ca-*.pem")
	if err != nil {
		log.Printf("%s: %v", n.ID, err)
		return
	}
	caPath := f.Name()
	defer os.Remove(caPath)
	err = f.Chmod(0600)
	if err == nil {
		_, err = f.Write(ca)
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		log.Printf("%s: %v", n.ID, err)
		return
	}
	h := registrationClient()
	defer h.CloseIdleConnections()
	if n.Kind == "lan" {
		tlsConfig, e := ClientTLS(ca)
		if e != nil {
			log.Printf("%s TLS: %v", n.ID, e)
			return
		}
		h.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
	if n.Kind == "public" {
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		roots.AppendCertsFromPEM(ca)
		h.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
	}
	h.Timeout = 5 * time.Second
	o := r.options
	o.Host = n.Host
	o.TunnelPort = n.TunnelPort
	var svc *client.Service
	var cancel context.CancelFunc
	var done chan struct{}
	token, last := "", ""
	stop := func() {
		r.mu.Lock()
		w.svc = nil
		w.grants = map[string]bool{}
		r.mu.Unlock()
		if cancel != nil {
			cancel()
			<-done
			cancel = nil
		}
		svc = nil
	}
	defer stop()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		var c DeviceConfig
		err = nil
		registering := token == ""
		if registering {
			reg := r.registration
			if r.identity != nil && r.identity.Enrolled {
				reg, err = signedRegistration(ctx, h, n.APIURL, r.identity, reg)
			}
			if err == nil {
				err = callAPI(ctx, h, "POST", n.APIURL+"/v1/register", "", "", reg, &c)
			}
		} else {
			err = callAPI(ctx, h, "GET", n.APIURL+"/v1/config", r.id, token, probeSSHService(o.SSHPort), &c)
		}
		if err != nil {
			var ae apiError
			if errors.As(err, &ae) && (ae.Status == 401 || ae.Status == 403) {
				token = ""
				stop()
				// A disabled device at the authority must never escape via a stale replica.
				if ae.Status == 403 && n.Kind == "public" {
					r.mu.Lock()
					r.blocked = true
					r.clearLocked()
					r.mu.Unlock()
				}
			}
			if ctx.Err() == nil {
				log.Printf("node %s control unavailable: %v", n.ID, err)
			}
		} else if c.ID != r.id || (registering && c.Token == "") {
			log.Printf("node %s returned invalid registration", n.ID)
		} else {
			if registering {
				token = c.Token
				stop()
				svc, err = newAgentService(o, hiddenPortConfig(c), token, caPath)
				if err != nil {
					log.Printf("node %s tunnel: %v", n.ID, err)
					token = ""
				} else {
					cancel, done = launchAgentService(ctx, svc)
				}
			}
			if svc != nil {
				b, _ := json.Marshal(c.Grants)
				if registering || last != string(b) {
					p, v := configs(hiddenPortConfig(c), o.SSHPort)
					if err = svc.UpdateAllConfigurer(p, v); err != nil {
						log.Printf("node %s permissions: %v", n.ID, err)
					} else {
						last = string(b)
					}
				}
				if err == nil {
					r.mu.Lock()
					w.svc = svc
					w.grants = map[string]bool{}
					for _, g := range c.Grants {
						w.grants[g.Target] = true
					}
					w.expires = c.Expires
					r.mu.Unlock()
					r.applyConfig(c, n.Kind == "public")
					if n.Kind == "public" && len(c.Nodes) > 0 {
						r.discover(c.Nodes)
					}
				}
			}
			if time.Until(c.Expires) < time.Minute {
				token = ""
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (r *agentRouter) applyConfig(c DeviceConfig, authority bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blocked && !authority {
		return
	}
	if c.PolicyRevision < r.revision || c.PolicyRevision == r.revision && c.PolicyIssued.Before(r.issued) {
		return
	}
	if authority {
		r.blocked = false
	}
	expires := c.PolicyExpires
	if expires.IsZero() {
		expires = c.Expires
	}
	if !time.Now().Before(expires) {
		return
	}
	r.revision, r.issued, r.expires = c.PolicyRevision, c.PolicyIssued, expires
	grants := map[string]Grant{}
	ports := map[int]Grant{}
	for _, g := range c.Grants {
		if g.Port < 1 || g.Port > 65535 {
			continue
		}
		grants[g.Target] = g
		ports[g.Port] = g
	}
	for port, l := range r.listeners {
		g, ok := ports[port]
		if !ok || g.Target != l.target {
			l.Close()
			delete(r.listeners, port)
		}
	}
	for conn, target := range r.active {
		if _, ok := grants[target]; !ok {
			conn.Close()
			delete(r.active, conn)
		}
	}
	r.grants = grants
	for port, g := range ports {
		if _, ok := r.listeners[port]; ok {
			continue
		}
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		if err != nil {
			log.Printf("SSH port %d: %v", port, err)
			continue
		}
		r.listeners[port] = routeListener{Listener: l, target: g.Target}
		log.Printf("%s (%s): ssh -p %d USER@127.0.0.1", g.Name, g.Target, port)
		go r.accept(l, g.Target)
	}
}
func (r *agentRouter) accept(l net.Listener, target string) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go r.forward(c, target)
	}
}

type routeCandidate struct {
	node Node
	svc  *client.Service
}

func (r *agentRouter) candidates(target string) []routeCandidate {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.grants[target]; !ok || r.blocked || !time.Now().Before(r.expires) {
		return nil
	}
	result := []routeCandidate{}
	for _, w := range r.workers {
		if w.svc != nil && w.grants[target] && time.Now().Before(w.expires) {
			result = append(result, routeCandidate{w.node, w.svc})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].node.Kind != result[j].node.Kind {
			return result[i].node.Kind == "lan"
		}
		return result[i].node.Priority < result[j].node.Priority
	})
	return result
}

// probeSSH reads only the target's identification. No client bytes are sent until
// a route is selected, so transport failure can safely fall back to another node.
func probeSSH(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, *bufio.Reader, []byte, error) {
	conn, err := dial(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetReadDeadline(deadline)
	}
	reader := bufio.NewReaderSize(conn, 8192)
	banner := []byte{}
	for len(banner) < 8192 {
		line, e := reader.ReadSlice('\n')
		banner = append(banner, line...)
		if e != nil {
			conn.Close()
			return nil, nil, nil, e
		}
		if strings.HasPrefix(string(line), "SSH-") {
			if !stop() || ctx.Err() != nil {
				conn.Close()
				return nil, nil, nil, context.DeadlineExceeded
			}
			conn.SetReadDeadline(time.Time{})
			return conn, reader, banner, nil
		}
	}
	conn.Close()
	return nil, nil, nil, fmt.Errorf("SSH identification exceeds 8192 bytes")
}
func (r *agentRouter) forward(local net.Conn, target string) {
	defer local.Close()
	r.mu.Lock()
	if _, ok := r.grants[target]; !ok || r.blocked || !time.Now().Before(r.expires) {
		r.mu.Unlock()
		return
	}
	r.active[local] = target
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.active, local); r.mu.Unlock() }()
	for _, candidate := range r.candidates(target) {
		budget := 5 * time.Second
		if candidate.node.Kind == "lan" {
			budget = 2 * time.Second
		}
		ctx, cancel := context.WithTimeout(r.ctx, budget)
		remote, reader, banner, err := probeSSH(ctx, func(ctx context.Context) (net.Conn, error) { return candidate.svc.DialSTCP(ctx, "to-"+target) })
		cancel()
		if err != nil {
			log.Printf("SSH %s via %s: %v", target, candidate.node.ID, err)
			if errors.Is(err, visitor.ErrAccessDenied) {
				return
			}
			continue
		}
		defer remote.Close()
		// Recheck authorization after the potentially slow handshake.
		r.mu.Lock()
		_, tracked := r.active[local]
		if tracked {
			r.active[remote] = target
		}
		r.mu.Unlock()
		if !tracked {
			return
		}
		defer func() { r.mu.Lock(); delete(r.active, remote); r.mu.Unlock() }()
		log.Printf("SSH %s routed via %s", target, candidate.node.ID)
		if _, err = local.Write(banner); err != nil {
			return
		}
		copied := make(chan struct{})
		go func() { io.Copy(remote, local); remote.Close(); close(copied) }()
		io.Copy(local, reader)
		local.Close()
		remote.Close()
		<-copied
		return
	}
}
