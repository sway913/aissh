package aissh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const DefaultHost = "connect.builderopc.com"
const DefaultAPIURL = "https://sshapi.builderopc.com"
const DefaultTunnelPort = 17000

var ErrDenied = errors.New("device or session disabled, expired, or unknown")

type Device struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Username string          `json:"username,omitempty"`
	Account  string          `json:"account,omitempty"`
	OS       string          `json:"os"`
	MACs     []string        `json:"macs"`
	Enabled  bool            `json:"enabled"`
	Admin    bool            `json:"admin"`
	Online   bool            `json:"online"`
	Created  time.Time       `json:"created"`
	LastSeen time.Time       `json:"lastSeen"`
	Secret   string          `json:"secret,omitempty"`
	Tunnels  map[string]bool `json:"tunnels,omitempty"`
}
type Rule struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	Port      int    `json:"port"`
	Automatic bool   `json:"automatic,omitempty"`
}
type state struct {
	Revision uint64             `json:"revision,omitempty"`
	Devices  map[string]*Device `json:"devices"`
	Rules    []Rule             `json:"rules"`
}
type session struct {
	DeviceID, Token string
	Expires         time.Time
}
type tracked struct{ Source, Target, RunID string }
type Store struct {
	replica             bool
	leaseExpires        time.Time
	leaseIssued         time.Time
	nodes               []Node
	nodeID              string
	tunnelOnline        func(string) bool
	reports             map[string]NodeReport
	heartbeats          map[string]time.Time
	registrations       map[string]Registration
	signingKey          []byte
	federation          *FederationConfig
	forwardRegistration func(context.Context, Registration) error
	clock               func() time.Time

	mu          sync.Mutex
	path        string
	state       state
	sessions    map[string]session
	connections map[net.Conn]tracked
}

func randomSecret() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func runID(token string) string { s := sha256.Sum256([]byte(token)); return hex.EncodeToString(s[:16]) }
func OpenStore(dir string) (*Store, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	s := &Store{path: filepath.Join(dir, "devices.json"), state: state{Devices: map[string]*Device{}, Rules: []Rule{}}, sessions: map[string]session{}, connections: map[net.Conn]tracked{}, reports: map[string]NodeReport{}, registrations: map[string]Registration{}, heartbeats: map[string]time.Time{}}
	b, e := os.ReadFile(s.path)
	if e == nil {
		if e = json.Unmarshal(b, &s.state); e != nil {
			return nil, e
		}
		if s.state.Devices == nil {
			return nil, fmt.Errorf("invalid device database")
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	return s, nil
}
func (s *Store) saveLocked() error {
	previous := s.state.Revision
	s.state.Revision++
	committed := false
	defer func() {
		if !committed {
			s.state.Revision = previous
		}
	}()
	b, e := json.MarshalIndent(s.state, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".devices-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), s.path); e != nil {
		return e
	}
	committed = true
	return nil
}

type Registration struct {
	Fingerprint Fingerprint `json:"fingerprint"`
	Name        string      `json:"name"`
	Username    string      `json:"username,omitempty"`
	Account     string      `json:"account,omitempty"`
	OS          string      `json:"os"`
}
type Grant struct {
	Target string `json:"target"`
	Name   string `json:"name"`
	Port   int    `json:"port"`
	Secret string `json:"secret"`
}
type DeviceConfig struct {
	ID             string    `json:"id"`
	Token          string    `json:"token,omitempty"`
	Expires        time.Time `json:"expires"`
	Secret         string    `json:"secret"`
	Grants         []Grant   `json:"grants"`
	Nodes          []Node    `json:"nodes,omitempty"`
	PolicyRevision uint64    `json:"policyRevision,omitempty"`
	PolicyIssued   time.Time `json:"policyIssued,omitempty"`
	PolicyExpires  time.Time `json:"policyExpires,omitempty"`
}

var ErrUnknownDevice = errors.New("device is not in the synchronized policy")

func (s *Store) now() time.Time {
	if s.clock != nil {
		return s.clock().UTC()
	}
	return time.Now().UTC()
}
func (s *Store) leaseValidLocked() bool { return !s.replica || s.now().Before(s.leaseExpires) }
func validRegistration(r Registration) (string, error) {
	id, e := r.Fingerprint.ID()
	if e != nil {
		return "", e
	}
	if len(r.Name) > 128 || len(r.OS) > 32 || len(r.Username) > 256 || len(r.Account) > 256 || strings.ContainsFunc(r.Username+r.Account, unicode.IsControl) {
		return "", fmt.Errorf("invalid device details")
	}
	return id, nil
}
func (s *Store) upsertLocked(r Registration, id string) (*Device, error) {
	now := s.now()
	d := s.state.Devices[id]
	if d != nil && !d.Enabled {
		return nil, ErrDenied
	}
	if d == nil {
		if s.replica {
			return nil, ErrUnknownDevice
		}
		if len(s.state.Devices) >= 1000 {
			return nil, fmt.Errorf("device limit reached")
		}
		d = &Device{ID: id, Name: r.Name, Username: r.Username, Account: r.Account, OS: r.OS, MACs: append([]string(nil), r.Fingerprint.MACs...), Enabled: true, Created: now, LastSeen: now, Secret: randomSecret()}
		oldRules := s.state.Rules
		s.state.Rules = append([]Rule{}, oldRules...)
		s.state.Devices[id] = d
		if e := s.syncAdminRulesLocked(); e != nil {
			delete(s.state.Devices, id)
			s.state.Rules = oldRules
			return nil, e
		}
		if e := s.saveLocked(); e != nil {
			s.state.Rules = oldRules
			delete(s.state.Devices, id)
			return nil, e
		}
	} else if !s.replica {
		old := *d
		d.Name, d.OS = r.Name, r.OS
		// Older clients omit these fields; keep previously reported account details.
		if r.Username != "" {
			d.Username = r.Username
		}
		if r.Account != "" {
			d.Account = r.Account
		}
		if d.Name != old.Name || d.OS != old.OS || d.Username != old.Username || d.Account != old.Account {
			if e := s.saveLocked(); e != nil {
				*d = old
				return nil, e
			}
		}
	}

	d.LastSeen = now
	return d, nil
}
func (s *Store) noteRegistration(r Registration) error {
	id, e := validRegistration(r)
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, e = s.upsertLocked(r, id)
	return e
}
func (s *Store) Register(r Registration) (DeviceConfig, error) {
	id, e := validRegistration(r)
	if e != nil {
		return DeviceConfig{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.leaseValidLocked() {
		return DeviceConfig{}, ErrDenied
	}
	_, e = s.upsertLocked(r, id)
	if e != nil {
		return DeviceConfig{}, e
	}
	if s.replica {
		s.registrations[id] = r
		s.heartbeats[id] = s.now()
	}
	for key, v := range s.sessions {
		if v.DeviceID == id {
			delete(s.sessions, key)
		}
	}
	v := session{DeviceID: id, Token: randomSecret(), Expires: s.now().Add(24 * time.Hour)}
	if s.replica && v.Expires.After(s.leaseExpires) {
		v.Expires = s.leaseExpires
	}
	s.sessions[runID(v.Token)] = v
	c := s.configLocked(v)
	c.Token = v.Token
	return c, nil
}
func (s *Store) sessionLocked(id, token string) (session, error) {
	v, ok := s.sessions[runID(token)]
	d := s.state.Devices[id]
	if !s.leaseValidLocked() || !ok || v.DeviceID != id || d == nil || !d.Enabled || !s.now().Before(v.Expires) || subtle.ConstantTimeCompare([]byte(v.Token), []byte(token)) != 1 {
		return session{}, ErrDenied
	}
	return v, nil
}
func (s *Store) Config(id, token string) (DeviceConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, e := s.sessionLocked(id, token)
	if e != nil {
		return DeviceConfig{}, e
	}
	s.state.Devices[id].LastSeen = s.now()
	if s.replica {
		s.heartbeats[id] = s.now()
	}
	return s.configLocked(v), nil
}
func (s *Store) configLocked(v session) DeviceConfig {
	d := s.state.Devices[v.DeviceID]
	c := DeviceConfig{ID: d.ID, Expires: v.Expires, Secret: d.Secret, Grants: []Grant{}, Nodes: append([]Node(nil), s.nodes...), PolicyRevision: s.state.Revision}
	if s.replica {
		c.PolicyIssued = s.leaseIssued
		c.PolicyExpires = s.leaseExpires
		if c.Expires.After(s.leaseExpires) {
			c.Expires = s.leaseExpires
		}
	} else {
		c.PolicyIssued = s.now()
		c.PolicyExpires = c.PolicyIssued.Add(24 * time.Hour)
	}
	for _, r := range s.state.Rules {
		t := s.state.Devices[r.Target]
		if r.Source == d.ID && t != nil && t.Enabled {
			c.Grants = append(c.Grants, Grant{Target: t.ID, Name: t.Name, Port: r.Port, Secret: t.Secret})
		}
	}
	sort.Slice(c.Grants, func(i, j int) bool { return c.Grants[i].Target < c.Grants[j].Target })
	return c
}
func (s *Store) Snapshot() ([]Device, []Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	active := make(map[string]bool, len(s.sessions))
	for _, session := range s.sessions {
		if now.Before(session.Expires) {
			active[session.DeviceID] = true
		}
	}
	ds := make([]Device, 0, len(s.state.Devices))
	for _, p := range s.state.Devices {
		d := *p
		d.Secret = ""
		if s.replica {
			d.LastSeen = s.heartbeats[d.ID]
		}
		// Evaluate heartbeats with the same clock that timestamps them. Browser
		// clocks may differ, and persisted heartbeats alone do not imply a session.
		d.Online = d.Enabled && s.leaseValidLocked() && active[d.ID] && now.Sub(d.LastSeen) < 30*time.Second
		d.Tunnels = map[string]bool{}
		if s.tunnelOnline != nil {
			d.Tunnels[s.nodeID] = d.Enabled && s.leaseValidLocked() && s.tunnelOnline(d.ID)
		}
		for node, report := range s.reports {
			if now.Sub(report.Received) < 30*time.Second {
				d.Tunnels[node] = d.Enabled && report.Tunnels[d.ID]
				if seen, ok := report.Seen[d.ID]; ok && now.Sub(seen) < 30*time.Second && d.Enabled {
					d.Online = true
					if seen.After(d.LastSeen) {
						d.LastSeen = seen
					}
				}
			} else {
				d.Tunnels[node] = false
			}
		}
		ds = append(ds, d)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].Created.Before(ds[j].Created) })
	rs := append([]Rule{}, s.state.Rules...)
	return ds, rs
}
func (s *Store) SetEnabled(id string, enabled bool) error {
	if s.replica {
		return fmt.Errorf("permissions are managed by the authority")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.state.Devices[id]
	if d == nil {
		return fmt.Errorf("unknown device")
	}
	old := d.Enabled
	d.Enabled = enabled
	if e := s.saveLocked(); e != nil {
		d.Enabled = old
		return e
	}
	if !enabled {
		for rid, v := range s.sessions {
			if v.DeviceID == id {
				delete(s.sessions, rid)
			}
		}
	}
	return nil
}

// DeleteDevice removes the device and both directions of its permissions.
// Sessions and active tunnels are revoked only after the database is saved.
func (s *Store) DeleteDevice(id string) error {
	if s.replica {
		return fmt.Errorf("permissions are managed by the authority")
	}
	s.mu.Lock()
	d := s.state.Devices[id]
	if d == nil {
		s.mu.Unlock()
		return fmt.Errorf("unknown device")
	}
	oldRules := s.state.Rules
	rules := make([]Rule, 0, len(oldRules))
	for _, r := range oldRules {
		if r.Source != id && r.Target != id {
			rules = append(rules, r)
		}
	}
	delete(s.state.Devices, id)
	s.state.Rules = rules
	if err := s.saveLocked(); err != nil {
		s.state.Devices[id] = d
		s.state.Rules = oldRules
		s.mu.Unlock()
		return err
	}
	for rid, v := range s.sessions {
		if v.DeviceID == id {
			delete(s.sessions, rid)
		}
	}
	s.mu.Unlock()
	s.RevokeConnections()
	return nil
}

// Materialize automatic grants at the authority so every node and older client
// receives the same stable local port assignments through the existing protocol.
func (s *Store) syncAdminRulesLocked() error {
	ids := make([]string, 0, len(s.state.Devices))
	for id := range s.state.Devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, source := range ids {
		if !s.state.Devices[source].Admin {
			continue
		}
		used, targets := map[int]bool{}, map[string]bool{}
		for _, r := range s.state.Rules {
			if r.Source == source {
				used[r.Port], targets[r.Target] = true, true
			}
		}
		for _, target := range ids {
			if target == source || targets[target] {
				continue
			}
			port := 22000
			for used[port] && port < 23000 {
				port++
			}
			if port == 23000 {
				return fmt.Errorf("too many permissions")
			}
			s.state.Rules = append(s.state.Rules, Rule{Source: source, Target: target, Port: port, Automatic: true})
			used[port] = true
		}
	}
	return nil
}

func (s *Store) SetAdmin(id string, admin bool) error {
	if s.replica {
		return fmt.Errorf("permissions are managed by the authority")
	}
	s.mu.Lock()
	d := s.state.Devices[id]
	if d == nil {
		s.mu.Unlock()
		return fmt.Errorf("unknown device")
	}
	oldAdmin, oldRules := d.Admin, s.state.Rules
	d.Admin = admin
	s.state.Rules = make([]Rule, 0, len(oldRules))
	for _, r := range oldRules {
		if !admin && r.Source == id && r.Automatic {
			continue
		}
		s.state.Rules = append(s.state.Rules, r)
	}
	err := s.syncAdminRulesLocked()
	if err == nil {
		err = s.saveLocked()
	}
	if err != nil {
		d.Admin, s.state.Rules = oldAdmin, oldRules
	}
	s.mu.Unlock()
	if err == nil {
		s.RevokeConnections()
	}
	return err
}

func (s *Store) SetRule(source, target string, allow bool) error {
	if s.replica {
		return fmt.Errorf("permissions are managed by the authority")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if source == target || s.state.Devices[source] == nil || s.state.Devices[target] == nil {
		return fmt.Errorf("invalid device pair")
	}
	if s.state.Devices[source].Admin {
		return fmt.Errorf("administrator devices already have automatic access; change their role first")
	}
	old := append([]Rule{}, s.state.Rules...)
	idx := -1
	for i, r := range s.state.Rules {
		if r.Source == source && r.Target == target {
			idx = i
			break
		}
	}
	if allow && idx < 0 {
		port := 22000
		for ; port < 23000; port++ {
			used := false
			for _, r := range s.state.Rules {
				if r.Source == source && r.Port == port {
					used = true
					break
				}
			}
			if !used {
				break
			}
		}
		if port == 23000 {
			return fmt.Errorf("too many permissions")
		}
		s.state.Rules = append(s.state.Rules, Rule{Source: source, Target: target, Port: port})
	} else if !allow && idx >= 0 {
		s.state.Rules = append(s.state.Rules[:idx], s.state.Rules[idx+1:]...)
	}
	if e := s.saveLocked(); e != nil {
		s.state.Rules = old
		return e
	}
	return nil
}
func (s *Store) allowedLocked(source, target, rid string) bool {
	v, ok := s.sessions[rid]
	a, b := s.state.Devices[source], s.state.Devices[target]
	if !s.leaseValidLocked() || !ok || v.DeviceID != source || !s.now().Before(v.Expires) || a == nil || b == nil || !a.Enabled || !b.Enabled {
		return false
	}
	for _, r := range s.state.Rules {
		if r.Source == source && r.Target == target && (!r.Automatic || a.Admin) {
			return true
		}
	}
	return false
}

type trackedConn struct {
	net.Conn
	store *Store
}

func (c *trackedConn) Close() error {
	c.store.mu.Lock()
	delete(c.store.connections, c)
	c.store.mu.Unlock()
	return c.Conn.Close()
}
func (s *Store) Track(conn net.Conn, source, target, rid string) (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.allowedLocked(source, target, rid) {
		return nil, ErrDenied
	}
	c := &trackedConn{Conn: conn, store: s}
	s.connections[c] = tracked{source, target, rid}
	return c, nil
}
func (s *Store) RevokeConnections() {
	s.mu.Lock()
	var cs []net.Conn
	for c, t := range s.connections {
		if !s.allowedLocked(t.Source, t.Target, t.RunID) {
			cs = append(cs, c)
			delete(s.connections, c)
		}
	}
	for k, v := range s.sessions {
		if !s.now().Before(v.Expires) {
			delete(s.sessions, k)
		}
	}
	s.mu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}
