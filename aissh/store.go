package aissh

import (
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
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Username string    `json:"username,omitempty"`
	Account  string    `json:"account,omitempty"`
	OS       string    `json:"os"`
	MACs     []string  `json:"macs"`
	Enabled  bool      `json:"enabled"`
	Online   bool      `json:"online"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"lastSeen"`
	Secret   string    `json:"secret,omitempty"`
}
type Rule struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Port   int    `json:"port"`
}
type state struct {
	Devices map[string]*Device `json:"devices"`
	Rules   []Rule             `json:"rules"`
}
type session struct {
	DeviceID, Token string
	Expires         time.Time
}
type tracked struct{ Source, Target, RunID string }
type Store struct {
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
	s := &Store{path: filepath.Join(dir, "devices.json"), state: state{Devices: map[string]*Device{}, Rules: []Rule{}}, sessions: map[string]session{}, connections: map[net.Conn]tracked{}}
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
	return os.Rename(f.Name(), s.path)
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
	ID      string    `json:"id"`
	Token   string    `json:"token,omitempty"`
	Expires time.Time `json:"expires"`
	Secret  string    `json:"secret"`
	Grants  []Grant   `json:"grants"`
}

func (s *Store) Register(r Registration) (DeviceConfig, error) {
	id, e := r.Fingerprint.ID()
	if e != nil {
		return DeviceConfig{}, e
	}
	if len(r.Name) > 128 || len(r.OS) > 32 || len(r.Username) > 256 || len(r.Account) > 256 || strings.ContainsFunc(r.Username+r.Account, unicode.IsControl) {
		return DeviceConfig{}, fmt.Errorf("invalid device details")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.state.Devices[id]
	if d != nil && !d.Enabled {
		return DeviceConfig{}, ErrDenied
	}
	now := time.Now().UTC()
	if d == nil {
		if len(s.state.Devices) >= 1000 {
			return DeviceConfig{}, fmt.Errorf("device limit reached")
		}
		d = &Device{ID: id, Name: r.Name, Username: r.Username, Account: r.Account, OS: r.OS, MACs: append([]string(nil), r.Fingerprint.MACs...), Enabled: true, Created: now, LastSeen: now, Secret: randomSecret()}
		s.state.Devices[id] = d
		if e = s.saveLocked(); e != nil {
			delete(s.state.Devices, id)
			return DeviceConfig{}, e
		}
	} else {
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
			if e = s.saveLocked(); e != nil {
				*d = old
				return DeviceConfig{}, e
			}
		}
	}
	d.LastSeen = now
	// Every startup gets a new temporary credential. It is never written to disk by the agent.
	for key, v := range s.sessions {
		if v.DeviceID == id {
			delete(s.sessions, key)
		}
	}
	v := session{DeviceID: id, Token: randomSecret(), Expires: now.Add(24 * time.Hour)}
	s.sessions[runID(v.Token)] = v
	c := s.configLocked(v)
	c.Token = v.Token
	return c, nil
}
func (s *Store) sessionLocked(id, token string) (session, error) {
	v, ok := s.sessions[runID(token)]
	d := s.state.Devices[id]
	if !ok || v.DeviceID != id || d == nil || !d.Enabled || time.Now().After(v.Expires) || subtle.ConstantTimeCompare([]byte(v.Token), []byte(token)) != 1 {
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
	s.state.Devices[id].LastSeen = time.Now().UTC()
	return s.configLocked(v), nil
}
func (s *Store) configLocked(v session) DeviceConfig {
	d := s.state.Devices[v.DeviceID]
	c := DeviceConfig{ID: d.ID, Expires: v.Expires, Secret: d.Secret, Grants: []Grant{}}
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
	now := time.Now()
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
		// Evaluate heartbeats with the same clock that timestamps them. Browser
		// clocks may differ, and persisted heartbeats alone do not imply a session.
		d.Online = d.Enabled && active[d.ID] && now.Sub(d.LastSeen) < 30*time.Second
		ds = append(ds, d)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].Created.Before(ds[j].Created) })
	rs := append([]Rule{}, s.state.Rules...)
	return ds, rs
}
func (s *Store) SetEnabled(id string, enabled bool) error {
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
func (s *Store) SetRule(source, target string, allow bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if source == target || s.state.Devices[source] == nil || s.state.Devices[target] == nil {
		return fmt.Errorf("invalid device pair")
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
	if !ok || v.DeviceID != source || time.Now().After(v.Expires) || a == nil || b == nil || !a.Enabled || !b.Enabled {
		return false
	}
	for _, r := range s.state.Rules {
		if r.Source == source && r.Target == target {
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
		if time.Now().After(v.Expires) {
			delete(s.sessions, k)
		}
	}
	s.mu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}
