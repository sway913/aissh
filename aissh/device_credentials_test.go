package aissh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func credentialIdentity(t *testing.T, fp Fingerprint) *DeviceIdentity {
	t.Helper()
	i, err := loadOrCreateIdentity(t.TempDir(), DefaultAPIURL, fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	return i
}
func proofFor(t *testing.T, s *Store, i *DeviceIdentity, r Registration) Registration {
	t.Helper()
	nonce, err := s.challenge()
	if err != nil {
		t.Fatal(err)
	}
	r, err = i.sign(r, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func migrateIdentity(t *testing.T, s *Store, i *DeviceIdentity, r Registration) string {
	t.Helper()
	r.Legacy = i.Legacy
	id, err := s.enroll(proofFor(t, s, i, r))
	if err != nil {
		t.Fatal(err)
	}
	i.ID = id
	i.Enrolled = true
	i.Legacy = nil
	return id
}
func TestPersistentIdentitySurvivesAdaptersAndRestart(t *testing.T) {
	dir := t.TempDir()
	fp := fingerprint("00:11:22:33:44:55")
	i, err := loadOrCreateIdentity(dir, DefaultAPIURL, fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldComputed, _ := fp.ID()
	if i.ID == oldComputed {
		t.Fatal("new identity must use random ID")
	}
	fp.MACs = []string{"02:ab:cd:ef:01:23"}
	second, err := loadOrCreateIdentity(dir, DefaultAPIURL, fp, []net.Interface{identityAdapter("en1", "36:96:32:28:20:c0")})
	if err != nil || !reflect.DeepEqual(i, second) {
		t.Fatalf("identity changed with adapter: %v", err)
	}
	fp.MACs = nil
	fp.Hardware = nil
	if again, err := loadOrCreateIdentity(dir, DefaultAPIURL, fp, nil); err != nil || again.ID != i.ID {
		t.Fatalf("missing observation changed identity: %v", err)
	}
	fp.Hardware = []string{strings.Repeat("a", 64)}
	if _, err := loadOrCreateIdentity(dir, DefaultAPIURL, fp, nil); err == nil {
		t.Fatal("cloned identity accepted on different hardware")
	}
	if _, err := loadOrCreateIdentity(dir, "https://other.example", fingerprint("00:11:22:33:44:55"), nil); err == nil {
		t.Fatal("silently rebound authority")
	}
	if err := os.WriteFile(identityPath(dir), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateIdentity(dir, DefaultAPIURL, fp, nil); err == nil {
		t.Fatal("corrupt identity replaced silently")
	}
}
func TestDeviceCredentialMigrationPreservesIDRoleRulesAndPort(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	oldReg := registration("00:11:22:33:44:55", "Mac")
	old, err := s.Register(oldReg)
	if err != nil {
		t.Fatal(err)
	}
	targetReg := registration("00:11:22:33:44:66", "Target")
	targetReg.Fingerprint.Hardware = []string{strings.Repeat("b", 64)}
	target, err := s.Register(targetReg)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetRule(old.ID, target.ID, true); err != nil {
		t.Fatal(err)
	}
	if err = s.SetAdmin(old.ID, true); err != nil {
		t.Fatal(err)
	}
	beforeRules := append([]Rule(nil), s.state.Rules...)
	beforeSecret := s.state.Devices[old.ID].Secret
	// The original MAC has disappeared. The persisted server record plus stable
	// platform hashes must find the existing ID, not create a duplicate.
	current := oldReg
	current.Fingerprint = fingerprint("02:aa:bb:cc:dd:ee")
	identity := credentialIdentity(t, current.Fingerprint)
	id := migrateIdentity(t, s, identity, current)
	if id != old.ID || len(s.state.Devices) != 2 || !s.state.Devices[id].Admin || s.state.Devices[id].Secret != beforeSecret || !reflect.DeepEqual(beforeRules, s.state.Rules) {
		t.Fatal("migration changed existing identity or grants")
	}
	if _, err = s.Config(old.ID, old.Token); err != ErrDenied {
		t.Fatalf("legacy session survived binding: %v", err)
	}
	if _, err = s.Register(oldReg); err != ErrDenied {
		t.Fatalf("hardware bypass after binding: %v", err)
	}
	signed := proofFor(t, s, identity, current)
	c, err := s.Register(signed)
	if err != nil || c.ID != old.ID || len(c.Grants) != 1 || c.Grants[0].Port != beforeRules[0].Port {
		t.Fatalf("signed login lost port: %v", err)
	}
	if _, err = s.Register(signed); err != ErrDenied {
		t.Fatalf("replayed proof accepted: %v", err)
	}
	reloaded, err := OpenStore(filepath.Dir(s.path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reloaded.Register(proofFor(t, reloaded, identity, current)); err != nil {
		t.Fatalf("credential binding lost on restart: %v", err)
	}
	attacker := credentialIdentity(t, current.Fingerprint)
	attackerReg := current
	attackerReg.Legacy = attacker.Legacy
	if _, err = s.enroll(proofFor(t, s, attacker, attackerReg)); err != ErrDenied {
		t.Fatalf("lost key bypass via hardware: %v", err)
	}
}
func TestDeviceProofTamperingExpiryAndServerRestart(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	now := time.Now().UTC()
	s.clock = func() time.Time { return now }
	r := registration("00:11:22:33:44:55", "A")
	i := credentialIdentity(t, r.Fingerprint)
	migrateIdentity(t, s, i, r)
	signed := proofFor(t, s, i, r)
	tampered := signed
	tampered.Username = "root"
	if _, err := s.Register(tampered); err != ErrDenied {
		t.Fatal("unsigned metadata change accepted")
	}
	now = now.Add(time.Minute)
	if _, err := s.Register(signed); err != ErrDenied {
		t.Fatal("expired challenge accepted")
	}
	signed = proofFor(t, s, i, r)
	restart, _ := OpenStore(filepath.Dir(s.path))
	if _, err := restart.Register(signed); err != ErrDenied {
		t.Fatal("pre-restart challenge accepted")
	}
	other, _ := OpenStore(t.TempDir())
	if err := other.consumeProofLocked(signed); err != ErrDenied {
		t.Fatal("cross-node proof accepted")
	}
	if err := s.SetEnabled(i.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(proofFor(t, s, i, r)); err != ErrDenied {
		t.Fatal("credential bypassed disable")
	}
}
func TestIdentityEnrollmentRetryAndSaveFailure(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	r := registration("00:11:22:33:44:55", "A")
	old, _ := s.Register(r)
	i := credentialIdentity(t, r.Fingerprint)
	request := r
	request.Legacy = i.Legacy
	id, err := s.enroll(proofFor(t, s, i, request))
	if err != nil || id != old.ID {
		t.Fatal(err)
	}
	retry, err := s.enroll(proofFor(t, s, i, request))
	if err != nil || retry != id || len(s.state.Devices) != 1 {
		t.Fatalf("lost response created duplicate: %v", err)
	}
	fresh, _ := OpenStore(t.TempDir())
	previousRevision := fresh.state.Revision
	fresh.path = filepath.Join(t.TempDir(), "missing", "devices.json")
	if _, err := fresh.enroll(proofFor(t, fresh, i, request)); err == nil {
		t.Fatal("enrollment ignored persistence failure")
	}
	if len(fresh.state.Devices) != 0 || len(fresh.state.Rules) != 0 || fresh.state.Revision != previousRevision {
		t.Fatal("failed enrollment changed policy")
	}
}
func TestDeviceCredentialHTTPEnrollmentAndLogin(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	server := httptest.NewTLSServer(DeviceHandler(s))
	defer server.Close()
	dir := t.TempDir()
	r := registration("00:11:22:33:44:55", "A")
	i, err := loadOrCreateIdentity(dir, server.URL, r.Fingerprint, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := i.ID
	if err = enrollIdentity(context.Background(), server.Client(), server.URL, dir, i, r); err != nil {
		t.Fatal(err)
	}
	if i.ID != expected || !i.Enrolled || len(i.Legacy) != 0 {
		t.Fatal("new device ID changed during enrollment")
	}
	again, err := loadOrCreateIdentity(dir, server.URL, r.Fingerprint, nil)
	if err != nil || again.ID != expected {
		t.Fatal(err)
	}
	signed, err := signedRegistration(context.Background(), server.Client(), server.URL, i, r)
	if err != nil {
		t.Fatal(err)
	}
	var c DeviceConfig
	if err = callAPI(context.Background(), server.Client(), "POST", server.URL+"/v1/register", "", "", signed, &c); err != nil || c.ID != expected {
		t.Fatalf("signed API login failed: %v", err)
	}
	if len(c.Grants) != 0 {
		t.Fatal("fresh registration granted privileges")
	}
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), i.PrivateKey) {
		t.Fatal("private key leaked")
	}
}
func TestCredentialReplicaOfflineRestartAndExpiry(t *testing.T) {
	now := time.Now().UTC()
	authority, _ := OpenStore(t.TempDir())
	authority.clock = func() time.Time { return now }
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	authority.signingKey = priv
	r := registration("00:11:22:33:44:55", "A")
	i := credentialIdentity(t, r.Fingerprint)
	migrateIdentity(t, authority, i, r)
	signed, err := authority.signedSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	makeReplica := func() *Store {
		replica, _ := OpenStore(dir)
		replica.replica = true
		replica.clock = func() time.Time { return now }
		replica.federation = &FederationConfig{PublicKey: base64.StdEncoding.EncodeToString(pub)}
		return replica
	}
	replica := makeReplica()
	if err = replica.applyPolicy(signed, false); err != nil {
		t.Fatal(err)
	}
	if _, err = replica.Register(proofFor(t, replica, i, r)); err != nil {
		t.Fatal(err)
	}
	if _, err = replica.Register(r); err != ErrDenied {
		t.Fatal("replica accepted legacy bypass")
	}
	if _, err = replica.enroll(proofFor(t, replica, i, r)); err == nil {
		t.Fatal("replica enrolled independently")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "policy-cache.json"))
	var envelope signedPolicy
	json.Unmarshal(raw, &envelope)
	restarted := makeReplica()
	if err = restarted.applyPolicy(envelope, true); err != nil {
		t.Fatal(err)
	}
	now = now.Add(23 * time.Hour)
	c, err := restarted.Register(proofFor(t, restarted, i, r))
	if err != nil || c.Expires.After(restarted.leaseExpires) {
		t.Fatalf("offline credential auth failed: %v", err)
	}
	now = now.Add(time.Hour)
	if _, err = restarted.challenge(); err != ErrDenied {
		t.Fatal("expired policy issued authentication challenge")
	}
	if _, err = restarted.Config(i.ID, c.Token); err != ErrDenied {
		t.Fatal("cached credential extended expired lease")
	}
}
func TestIdentityLockAndStartupIdentityTransfer(t *testing.T) {
	source, dest := t.TempDir(), t.TempDir()
	fp := fingerprint("00:11:22:33:44:55")
	original, err := loadOrCreateIdentity(source, DefaultAPIURL, fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockAgentIdentity(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = lockAgentIdentity(source); err == nil {
		t.Fatal("two agents own one identity")
	}
	if err = copyStartupIdentity(source, dest, DefaultAPIURL); err == nil {
		t.Fatal("copied a live identity into another process")
	}
	unlock()
	if err = copyStartupIdentity(source, dest, DefaultAPIURL); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(identityPath(source)); !os.IsNotExist(err) {
		t.Fatal("retained old duplicate credential")
	}
	migrated, err := loadOrCreateIdentity(dest, DefaultAPIURL, fp, nil)
	if err != nil || !reflect.DeepEqual(original, migrated) {
		t.Fatal("startup installation changed identity")
	}
	f, err := os.Open(identityPath(dest))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = io.ReadAll(f); err != nil {
		t.Fatal(err)
	}
}

func TestStartupAndForegroundShareIdentityDirectory(t *testing.T) {
	installed := StartupConfig{Options: AgentOptions{StateDir: filepath.Join(t.TempDir(), "shared")}, Username: "qihoo", Account: "qihoo", UID: 501, GID: 20}
	foreground := AgentOptions{StateDir: filepath.Join(t.TempDir(), "user-default"), APIURL: DefaultAPIURL}
	resolved, err := resolveAgentIdentityOptions(foreground, func() (StartupConfig, error) { return installed, nil })
	if err != nil || resolved.StateDir != installed.Options.StateDir || resolved.ManagedIdentity == nil || resolved.ManagedIdentity.Username != "qihoo" {
		t.Fatal("foreground used another identity directory")
	}
	fp := fingerprint("00:11:22:33:44:55")
	first, err := loadOrCreateIdentity(resolved.StateDir, DefaultAPIURL, fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateIdentity(installed.Options.StateDir, DefaultAPIURL, fp, nil)
	if err != nil || second.ID != first.ID || second.PrivateKey != first.PrivateKey {
		t.Fatal("service generated a separate identity")
	}
	foreground.StateDirExplicit = true
	resolved, err = resolveAgentIdentityOptions(foreground, func() (StartupConfig, error) {
		t.Fatal("explicit installation unexpectedly read global config")
		return installed, nil
	})
	if err != nil || resolved.StateDir != foreground.StateDir {
		t.Fatal("explicit directory ignored")
	}
}
func TestBindingReclaimsLegacyConnectionsAndReplicaSessions(t *testing.T) {
	now := time.Now().UTC()
	authority, _ := OpenStore(t.TempDir())
	authority.clock = func() time.Time { return now }
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	authority.signingKey = priv
	r := registration("00:11:22:33:44:55", "A")
	source, _ := authority.Register(r)
	targetReg := registration("00:11:22:33:44:66", "B")
	targetReg.Fingerprint.Hardware = []string{strings.Repeat("b", 64)}
	target, _ := authority.Register(targetReg)
	authority.SetRule(source.ID, target.ID, true)
	replica, _ := OpenStore(t.TempDir())
	replica.replica = true
	replica.clock = func() time.Time { return now }
	replica.federation = &FederationConfig{PublicKey: base64.StdEncoding.EncodeToString(pub)}
	before, _ := authority.signedSnapshot()
	if err := replica.applyPolicy(before, false); err != nil {
		t.Fatal(err)
	}
	replicaSource, err := replica.Register(r)
	if err != nil {
		t.Fatal(err)
	}
	replica.Register(targetReg)
	a, b := net.Pipe()
	defer b.Close()
	tracked, err := authority.Track(a, source.ID, target.ID, runID(source.Token))
	if err != nil {
		t.Fatal(err)
	}
	defer tracked.Close()
	c, d := net.Pipe()
	defer d.Close()
	replicaTracked, err := replica.Track(c, source.ID, target.ID, runID(replicaSource.Token))
	if err != nil {
		t.Fatal(err)
	}
	defer replicaTracked.Close()
	i := credentialIdentity(t, r.Fingerprint)
	migrateIdentity(t, authority, i, r)
	b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = b.Read(make([]byte, 1)); err == nil {
		t.Fatal("authority retained unbound stream")
	}
	after, _ := authority.signedSnapshot()
	if err = replica.applyPolicy(after, false); err != nil {
		t.Fatal(err)
	}
	d.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = d.Read(make([]byte, 1)); err == nil {
		t.Fatal("replica retained unbound stream")
	}
	if _, err = replica.Config(source.ID, replicaSource.Token); err != ErrDenied {
		t.Fatal("replica retained unbound session")
	}
	if _, err = replica.Register(proofFor(t, replica, i, r)); err != nil {
		t.Fatalf("bound credential did not reconnect: %v", err)
	}
}

func TestForegroundRejectsLegacyServiceWithoutIdentityLock(t *testing.T) {
	if err := checkForegroundStartup(&fakeStartup{state: startupStatus{Installed: true, Running: true, Enabled: true}}); err == nil {
		t.Fatal("foreground started alongside pre-credential service")
	}
	if err := checkForegroundStartup(&fakeStartup{state: startupStatus{Installed: true}}); err != nil {
		t.Fatal(err)
	}
}
