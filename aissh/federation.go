package aissh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const policyLifetime = 24 * time.Hour

// Node is public discovery metadata, never a node credential or private key.
type Node struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Kind       string `json:"kind"`
	APIURL     string `json:"apiURL"`
	Host       string `json:"host"`
	TunnelPort int    `json:"tunnelPort"`
	Priority   int    `json:"priority"`
	CAPEM      string `json:"caPEM,omitempty"`
}
type FederationConfig struct {
	Role         string            `json:"role"`
	NodeID       string            `json:"nodeID"`
	AuthorityURL string            `json:"authorityURL,omitempty"`
	PublicKey    string            `json:"publicKey,omitempty"`
	Token        string            `json:"token,omitempty"`
	NodeTokens   map[string]string `json:"nodeTokens,omitempty"`
	Nodes        []Node            `json:"nodes"`
}
type policySnapshot struct {
	State   state     `json:"state"`
	Nodes   []Node    `json:"nodes"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
}
type signedPolicy struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}
type NodeReport struct {
	ID            string               `json:"id"`
	Seen          map[string]time.Time `json:"seen"`
	Tunnels       map[string]bool      `json:"tunnels"`
	Registrations []Registration       `json:"registrations,omitempty"`
	Applied       time.Time            `json:"applied"`
	Expires       time.Time            `json:"expires"`
	Received      time.Time            `json:"-"`
}
type NodeStatus struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Kind      string    `json:"kind"`
	Connected bool      `json:"connected"`
	SyncedAt  time.Time `json:"syncedAt"`
	Expires   time.Time `json:"expires"`
}

func atomicPrivate(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".aissh-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func validNodes(nodes []Node) error {
	if len(nodes) > 8 {
		return fmt.Errorf("too many nodes")
	}
	ids := map[string]bool{}
	for _, n := range nodes {
		if n.ID == "" || ids[n.ID] || n.Host == "" || n.TunnelPort < 1 || n.TunnelPort > 65535 || n.Kind != "lan" && n.Kind != "public" {
			return fmt.Errorf("invalid node")
		}
		ids[n.ID] = true
		if _, err := registrationURL(n.APIURL); err != nil {
			return err
		}
		if n.CAPEM != "" {
			if _, err := ClientTLS([]byte(n.CAPEM)); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Store) configureFederation(file string) error {
	s.nodeID = "hongkong"
	if file == "" {
		return nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var c FederationConfig
	if err = json.Unmarshal(b, &c); err != nil {
		return err
	}
	if c.NodeID == "" || c.Role != "authority" && c.Role != "replica" {
		return fmt.Errorf("invalid federation role or node ID")
	}
	if err = validNodes(c.Nodes); err != nil {
		return err
	}
	found := false
	for _, n := range c.Nodes {
		if n.ID == c.NodeID {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("local node missing from discovery")
	}
	s.federation = &c
	s.nodeID = c.NodeID
	s.nodes = c.Nodes
	s.replica = c.Role == "replica"
	if !s.replica {
		path := filepath.Join(filepath.Dir(s.path), "policy-signing.key")
		key, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			_, priv, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				return e
			}
			key = priv
			err = atomicPrivate(path, key)
		}
		if err != nil {
			return err
		}
		if len(key) != ed25519.PrivateKeySize {
			return fmt.Errorf("invalid policy signing key")
		}
		s.signingKey = key
		for id, token := range c.NodeTokens {
			if id == "" || len(token) < 32 {
				return fmt.Errorf("invalid node credential")
			}
		}
		return nil
	}
	if _, err = registrationURL(c.AuthorityURL); err != nil {
		return err
	}
	if len(c.Token) < 32 {
		return fmt.Errorf("missing node credential")
	}
	key, err := base64.StdEncoding.DecodeString(c.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid authority public key")
	}
	s.state = state{Devices: map[string]*Device{}, Rules: []Rule{}}
	path := filepath.Join(filepath.Dir(s.path), "policy-cache.json")
	if b, err = os.ReadFile(path); err == nil {
		var signed signedPolicy
		if err = json.Unmarshal(b, &signed); err != nil {
			return err
		}
		if err = s.applyPolicy(signed, true); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	s.forwardRegistration = func(ctx context.Context, r Registration) error {
		var signed signedPolicy
		if err := s.nodeCall(ctx, "/v1/node/register", r, &signed); err != nil {
			return err
		}
		return s.applyPolicy(signed, false)
	}
	return nil
}
func (s *Store) signedSnapshot() (signedPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	payload, err := json.Marshal(policySnapshot{State: s.state, Nodes: s.nodes, Issued: now, Expires: now.Add(policyLifetime)})
	if err != nil {
		return signedPolicy{}, err
	}
	if len(s.signingKey) != ed25519.PrivateKeySize {
		return signedPolicy{}, fmt.Errorf("authority signing disabled")
	}
	return signedPolicy{Payload: payload, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.signingKey, payload))}, nil
}
func (s *Store) applyPolicy(signed signedPolicy, loading bool) error {
	key, err := base64.StdEncoding.DecodeString(s.federation.PublicKey)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, signed.Payload, sig) {
		return fmt.Errorf("invalid policy signature")
	}
	var policy policySnapshot
	if err = json.Unmarshal(signed.Payload, &policy); err != nil {
		return err
	}
	if err = validNodes(policy.Nodes); err != nil {
		return err
	}
	s.mu.Lock()
	now := s.now()
	if policy.Issued.After(now.Add(2*time.Minute)) || policy.Expires.Sub(policy.Issued) != policyLifetime || (!loading && !now.Before(policy.Expires)) || policy.State.Devices == nil || policy.State.Revision < s.state.Revision || policy.Issued.Before(s.leaseIssued) {
		s.mu.Unlock()
		return fmt.Errorf("expired, future or rolled back policy")
	}
	if policy.Issued.Equal(s.leaseIssued) && policy.State.Revision == s.state.Revision {
		s.mu.Unlock()
		return nil
	}
	// Persist the signed envelope itself: a restart cannot manufacture a new lease.
	b, err := json.Marshal(signed)
	if err == nil && !loading {
		err = atomicPrivate(filepath.Join(filepath.Dir(s.path), "policy-cache.json"), b)
	}
	if err != nil {
		s.mu.Unlock()
		return err
	}
	for id, d := range policy.State.Devices {
		if old := s.state.Devices[id]; old != nil && old.LastSeen.After(d.LastSeen) {
			d.LastSeen = old.LastSeen
		}
	}
	s.state = policy.State
	s.nodes = policy.Nodes
	s.leaseIssued = policy.Issued
	s.leaseExpires = policy.Expires
	s.mu.Unlock()
	s.RevokeConnections()
	return nil
}
func (s *Store) nodeCall(ctx context.Context, path string, body, out any) error {
	h := registrationClient()
	defer h.CloseIdleConnections()
	h.Timeout = 5 * time.Second
	return callAPI(ctx, h, "POST", s.federation.AuthorityURL+path, s.nodeID, s.federation.Token, body, out)
}
func (s *Store) report() NodeReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := NodeReport{ID: s.nodeID, Seen: map[string]time.Time{}, Tunnels: map[string]bool{}, Applied: s.leaseIssued, Expires: s.leaseExpires}
	for id := range s.state.Devices {
		if seen := s.heartbeats[id]; s.now().Sub(seen) < 30*time.Second {
			r.Seen[id] = seen
		}
		if s.tunnelOnline != nil && s.leaseValidLocked() {
			r.Tunnels[id] = s.tunnelOnline(id)
		}
	}
	for id, reg := range s.registrations {
		if _, ok := r.Seen[id]; ok {
			r.Registrations = append(r.Registrations, reg)
		}
	}
	return r
}
func (s *Store) runReplica(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		var signed signedPolicy
		if err := s.nodeCall(ctx, "/v1/node/sync", s.report(), &signed); err != nil {
			if ctx.Err() == nil {
				log.Printf("authority sync unavailable: %v", err)
			}
		} else if err = s.applyPolicy(signed, false); err != nil {
			log.Printf("reject authority policy: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Store) federationHandler(next http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", next)
	authenticated := func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if s.federation == nil || s.replica {
				http.NotFound(w, r)
				return
			}
			id := r.Header.Get("X-Aissh-Device")
			expected := s.federation.NodeTokens[id]
			actual := r.Header.Get("Authorization")
			if expected == "" || subtle.ConstantTimeCompare([]byte(actual), []byte("Bearer "+expected)) != 1 {
				fail(w, 401, "node authentication required")
				return
			}
			handler(w, r)
		}
	}
	mux.HandleFunc("POST /v1/node/sync", authenticated(func(w http.ResponseWriter, r *http.Request) {
		var report NodeReport
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil || report.ID != r.Header.Get("X-Aissh-Device") || len(report.Registrations) > 1000 || len(report.Seen) > 1000 || len(report.Tunnels) > 1000 {
			fail(w, 400, "invalid node report")
			return
		}
		for _, reg := range report.Registrations {
			id, err := validRegistration(reg)
			if err != nil {
				continue
			}
			s.mu.Lock()
			// Reports may refresh existing metadata, never resurrect deleted devices.
			if s.state.Devices[id] != nil {
				_, _ = s.upsertLocked(reg, id)
			}
			s.mu.Unlock()
		}
		s.mu.Lock()
		report.Received = s.now()
		s.reports[report.ID] = report
		s.mu.Unlock()
		signed, err := s.signedSnapshot()
		if err != nil {
			fail(w, 503, "snapshot unavailable")
			return
		}
		respond(w, 200, signed)
	}))
	mux.HandleFunc("POST /v1/node/register", authenticated(func(w http.ResponseWriter, r *http.Request) {
		var reg Registration
		if err := decode(w, r, &reg); err != nil {
			fail(w, 400, "invalid registration")
			return
		}
		if err := s.noteRegistration(reg); err != nil {
			if err == ErrDenied {
				fail(w, 403, "device disabled")
			} else {
				fail(w, 400, "invalid registration")
			}
			return
		}
		signed, err := s.signedSnapshot()
		if err != nil {
			fail(w, 503, "snapshot unavailable")
			return
		}
		respond(w, 200, signed)
	}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		valid := s.leaseValidLocked()
		s.mu.Unlock()
		if !valid {
			fail(w, 503, "policy unavailable or expired")
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	return mux
}
func (s *Store) nodeStatuses() []NodeStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []NodeStatus{}
	for _, n := range s.nodes {
		v := NodeStatus{ID: n.ID, Label: n.Label, Kind: n.Kind}
		if n.ID == s.nodeID {
			v.Connected = true
		} else if r, ok := s.reports[n.ID]; ok {
			v.Connected = s.now().Sub(r.Received) < 30*time.Second
			v.SyncedAt = r.Applied
			v.Expires = r.Expires
		}
		result = append(result, v)
	}
	return result
}

// ReadFederationPublicKey exports only the signing public key for node provisioning.
func ReadFederationPublicKey(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "policy-signing.key"))
	if err != nil {
		return "", err
	}
	if len(b) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid signing key")
	}
	return base64.StdEncoding.EncodeToString(ed25519.PrivateKey(b).Public().(ed25519.PublicKey)), nil
}
