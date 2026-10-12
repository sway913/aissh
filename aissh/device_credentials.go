package aissh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DeviceIdentity is private, local state. It is never included in startup
// configuration, releases, node snapshots, logs, or API responses.
type DeviceIdentity struct {
	Version    int           `json:"version"`
	ID         string        `json:"id"`
	PrivateKey string        `json:"privateKey"`
	Authority  string        `json:"authority"`
	Enrolled   bool          `json:"enrolled"`
	Hardware   []string      `json:"hardware,omitempty"`
	Legacy     []Fingerprint `json:"legacy,omitempty"`
}

func validDeviceID(id string) bool {
	if !strings.HasPrefix(id, "dev-") || len(id) != 36 {
		return false
	}
	b, err := hex.DecodeString(id[4:])
	return err == nil && len(b) == 16
}
func sameStrings(a, b []string) bool {
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\n") == strings.Join(b, "\n")
}

// Missing observations are inconclusive, rather than proof of replacement.
func hardwareMismatch(saved, current []string) bool {
	if len(saved) == 0 || len(current) == 0 {
		return false
	}
	for _, a := range saved {
		for _, b := range current {
			if a == b {
				return false
			}
		}
	}
	return true
}
func (i *DeviceIdentity) key() (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(i.PrivateKey)
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid saved device credential; restore identity.json from backup")
	}
	key := ed25519.NewKeyFromSeed(b[:ed25519.SeedSize])
	if !bytes.Equal(key, b) {
		return nil, fmt.Errorf("corrupt saved device credential")
	}
	return key, nil
}
func identityPath(dir string) string { return filepath.Join(dir, "identity.json") }
func saveDeviceIdentity(dir string, i *DeviceIdentity) error {
	b, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	return atomicPrivate(identityPath(dir), b)
}
func loadOrCreateIdentity(dir, authority string, fp Fingerprint, adapters []net.Interface, previousHardware ...[]string) (*DeviceIdentity, error) {
	path := identityPath(dir)
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing identity symlink")
	}
	b, err := os.ReadFile(path)
	if err == nil {
		var i DeviceIdentity
		if json.Unmarshal(b, &i) != nil || i.Version != 1 || !validDeviceID(i.ID) || i.Authority != authority {
			return nil, fmt.Errorf("invalid identity or authority changed; restore the original identity/configuration")
		}
		if _, err = i.key(); err != nil {
			return nil, err
		}
		if hardwareMismatch(i.Hardware, fp.Hardware) {
			return nil, fmt.Errorf("device hardware differs from saved identity; possible cloned identity, contact administrator")
		}
		return &i, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	idBytes := make([]byte, 16)
	if _, err = rand.Read(idBytes); err != nil {
		return nil, err
	}
	i := &DeviceIdentity{Version: 1, ID: "dev-" + hex.EncodeToString(idBytes), PrivateKey: base64.StdEncoding.EncodeToString(key), Authority: authority, Hardware: append([]string(nil), fp.Hardware...)}
	// The old ID used one selected MAC. Try all currently available adapters once
	// during migration; the authority chooses the most recently used existing ID.
	if _, err := fp.ID(); err == nil {
		i.Legacy = []Fingerprint{fp}
	}
	if len(fp.MACs) == 0 && len(fp.Hardware) == 0 {
		return nil, fmt.Errorf("no hardware information available for first enrollment; retry after system startup")
	}
	seen := map[string]bool{}
	if id, err := fp.ID(); err == nil {
		seen[id] = true
	}
	hardwareVariants := append([][]string{fp.Hardware}, previousHardware...)
	for _, hardware := range hardwareVariants {
		for _, a := range adapters {
			m := a.HardwareAddr
			if a.Flags&net.FlagLoopback != 0 || len(m) != 6 || m[0]&1 != 0 || m.String() == "00:00:00:00:00:00" {
				continue
			}
			f := Fingerprint{MACs: []string{m.String()}, Hardware: append([]string(nil), hardware...)}
			id, e := f.ID()
			if e == nil && !seen[id] && len(i.Legacy) < 32 {
				i.Legacy = append(i.Legacy, f)
				seen[id] = true
			}
		}
	}
	if err = saveDeviceIdentity(dir, i); err != nil {
		return nil, err
	}
	return i, nil
}
func registrationPayload(r Registration) []byte {
	r.Signature = ""
	b, _ := json.Marshal(r)
	return append([]byte("aissh-device-proof-v1\n"), b...)
}
func (i *DeviceIdentity) sign(r Registration, challenge string) (Registration, error) {
	key, err := i.key()
	if err != nil {
		return r, err
	}
	r.DeviceID = i.ID
	r.PublicKey = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	r.Challenge = challenge
	r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, registrationPayload(r)))
	return r, nil
}
func validProof(r Registration) bool {
	pub, e := base64.StdEncoding.DecodeString(r.PublicKey)
	if e != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, e := base64.StdEncoding.DecodeString(r.Signature)
	return e == nil && ed25519.Verify(pub, registrationPayload(r), sig)
}
func (s *Store) challenge() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.leaseValidLocked() {
		return "", ErrDenied
	}
	if s.challenges == nil {
		s.challenges = map[string]time.Time{}
	}
	now := s.now()
	for n, e := range s.challenges {
		if !now.Before(e) {
			delete(s.challenges, n)
		}
	}
	if len(s.challenges) >= 8192 {
		return "", fmt.Errorf("too many authentication challenges")
	}
	n := randomSecret()
	s.challenges[n] = now.Add(time.Minute)
	return n, nil
}
func (s *Store) consumeProofLocked(r Registration) error {
	expires, ok := s.challenges[r.Challenge]
	if !ok || !s.now().Before(expires) || !validProof(r) {
		return ErrDenied
	}
	delete(s.challenges, r.Challenge)
	return nil
}
func (s *Store) checkCredentialLocked(r Registration, id string, consume bool) error {
	d := s.state.Devices[id]
	if r.DeviceID == "" && r.PublicKey == "" && r.Signature == "" && r.Challenge == "" && len(r.Legacy) == 0 {
		if d != nil && d.PublicKey != "" {
			return ErrDenied
		}
		if len(r.Fingerprint.Hardware) > 0 {
			for _, bound := range s.state.Devices {
				if bound.PublicKey != "" && sameStrings(bound.Hardware, r.Fingerprint.Hardware) {
					return ErrDenied
				}
			}
		}
		return nil // Existing clients remain usable until this device migrates.
	}
	if d == nil {
		return ErrUnknownDevice
	}
	if d.PublicKey == "" || d.PublicKey != r.PublicKey || !validProof(r) {
		return ErrDenied
	}
	if consume {
		return s.consumeProofLocked(r)
	}
	return nil
}

// enroll is a one-time upgrade of an unbound legacy identity. Hardware was not
// an authentication secret in that protocol. Once bound, only the device key
// can recover it; a lost key never silently falls back to hardware enrollment.
func (s *Store) enroll(r Registration) (string, error) {
	if _, err := validRegistration(r); err != nil {
		return "", err
	}
	if r.DeviceID == "" || len(r.Legacy) > 32 {
		return "", ErrDenied
	}
	s.mu.Lock()
	var revoked []net.Conn
	defer func() {
		s.mu.Unlock()
		for _, c := range revoked {
			c.Close()
		}
	}()
	if s.replica {
		return "", fmt.Errorf("first enrollment requires the authority")
	}
	if err := s.consumeProofLocked(r); err != nil {
		return "", err
	}
	id := r.DeviceID
	// A retry after an interrupted response must recover the same binding.
	if d := s.state.Devices[id]; d != nil {
		if d.PublicKey != r.PublicKey || !d.Enabled {
			return "", ErrDenied
		}
		return id, nil
	}
	var selected *Device
	candidates := map[string]bool{}
	hardwareVariants := [][]string{r.Fingerprint.Hardware}
	for _, fp := range r.Legacy {
		candidate, err := fp.ID()
		if err != nil {
			return "", ErrDenied
		}
		candidates[candidate] = true
		hardwareVariants = append(hardwareVariants, fp.Hardware)
	}
	// An old adapter may already have disappeared. Stored legacy MAC + the
	// observed hardware hashes can still reproduce its exact old ID. Never
	// merge by hostname, username, or MAC alone.
	for _, d := range s.state.Devices {
		if d.PublicKey != "" && len(d.Hardware) > 0 && sameStrings(d.Hardware, r.Fingerprint.Hardware) {
			candidates[d.ID] = true
		}
	}
	fallback := len(candidatesWithRecords(candidates, s.state.Devices)) == 0
	if len(r.Fingerprint.Hardware) > 0 && fallback {
		for _, d := range s.state.Devices {
			if d.OS != r.OS {
				continue
			}
			for _, hardware := range hardwareVariants {
				if len(hardware) == 0 {
					continue
				}
				fp := Fingerprint{MACs: d.MACs, Hardware: hardware}
				candidate, err := fp.ID()
				if err == nil && candidate == d.ID {
					candidates[candidate] = true
				}
			}
		}
	}
	if len(candidatesWithRecords(candidates, s.state.Devices)) > 1 && fallback {
		return "", ErrDenied
	}
	for candidate := range candidates {
		if d := s.state.Devices[candidate]; d != nil && d.PublicKey == r.PublicKey {
			if !d.Enabled {
				return "", ErrDenied
			}
			return d.ID, nil
		}
	}
	for candidate := range candidates {
		if d := s.state.Devices[candidate]; d != nil {
			if d.PublicKey != "" {
				if d.PublicKey != r.PublicKey || !d.Enabled {
					return "", ErrDenied
				}
				return d.ID, nil
			}
			if selected == nil || d.LastSeen.After(selected.LastSeen) || d.LastSeen.Equal(selected.LastSeen) && d.ID < selected.ID {
				selected = d
			}
		}
	}
	if selected != nil {
		if !selected.Enabled || selected.OS != r.OS || selected.PublicKey != "" && selected.PublicKey != r.PublicKey {
			return "", ErrDenied
		}
		id = selected.ID
		if selected.PublicKey == r.PublicKey {
			return id, nil
		}
	}
	oldRules := s.state.Rules
	var old Device
	if selected == nil {
		if len(s.state.Devices) >= 1000 {
			return "", fmt.Errorf("device limit reached")
		}
		selected = &Device{ID: id, Name: r.Name, OS: r.OS, Username: r.Username, Account: r.Account, MACs: append([]string(nil), r.Fingerprint.MACs...), Enabled: true, Created: s.now(), Secret: randomSecret()}
	} else {
		old = *selected
	}
	selected.PublicKey = r.PublicKey
	selected.Hardware = append([]string(nil), r.Fingerprint.Hardware...)
	selected.LastSeen = s.now()
	s.state.Devices[id] = selected
	s.state.Rules = append([]Rule{}, oldRules...)
	err := s.syncAdminRulesLocked()
	if err == nil {
		err = s.saveLocked()
	}
	if err != nil {
		if old.ID == "" {
			delete(s.state.Devices, id)
		} else {
			*selected = old
		}
		s.state.Rules = oldRules
		return "", err
	}
	// Legacy sessions cannot continue authenticating after the key is bound.
	for rid, v := range s.sessions {
		if v.DeviceID == id {
			delete(s.sessions, rid)
		}
	}
	for c, t := range s.connections {
		if t.Source == id || t.Target == id {
			revoked = append(revoked, c)
			delete(s.connections, c)
		}
	}
	return id, nil
}
func signedRegistration(ctx context.Context, h *http.Client, base string, i *DeviceIdentity, r Registration) (Registration, error) {
	var c struct {
		Challenge string `json:"challenge"`
	}
	if err := callAPI(ctx, h, "POST", base+"/v1/identity/challenge", "", "", struct{}{}, &c); err != nil {
		return r, err
	}
	return i.sign(r, c.Challenge)
}
func enrollIdentity(ctx context.Context, h *http.Client, base, dir string, i *DeviceIdentity, r Registration) error {
	if i.Enrolled {
		return nil
	}
	r.Legacy = i.Legacy
	signed, err := signedRegistration(ctx, h, base, i, r)
	if err != nil {
		return err
	}
	var result struct {
		ID string `json:"id"`
	}
	if err = callAPI(ctx, h, "POST", base+"/v1/identity/enroll", "", "", signed, &result); err != nil {
		return err
	}
	if !validDeviceID(result.ID) {
		return fmt.Errorf("invalid enrollment response")
	}
	// Keep pending state on disk if persistence fails. The same key can retry.
	next := *i
	next.ID = result.ID
	next.Enrolled = true
	next.Legacy = nil
	if len(next.Hardware) == 0 {
		next.Hardware = append([]string(nil), r.Fingerprint.Hardware...)
	}
	if err = saveDeviceIdentity(dir, &next); err != nil {
		return err
	}
	*i = next
	return nil
}
func waitEnrollment(ctx context.Context, o AgentOptions, i *DeviceIdentity, r Registration) error {
	h := registrationClient()
	ca, err := TrustPEM(o.CAFile)
	if err != nil {
		return err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	roots.AppendCertsFromPEM(ca)
	h.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
	defer h.CloseIdleConnections()
	for {
		err := enrollIdentity(ctx, h, o.APIURL, o.StateDir, i, r)
		if err == nil {
			return nil
		}
		var ae apiError
		if errors.As(err, &ae) && ae.Status == 403 {
			return fmt.Errorf("identity enrollment rejected; restore the existing identity file or contact administrator: %w", err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Never start legacy tunnels or invent another identity when enrollment fails.
		log.Printf("device enrollment unavailable: %v", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
}

func candidatesWithRecords(candidates map[string]bool, devices map[string]*Device) []string {
	ids := []string{}
	for id := range candidates {
		if devices[id] != nil {
			ids = append(ids, id)
		}
	}
	return ids
}
