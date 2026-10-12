package aissh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignedPolicyOfflineRestartExpiryAndRevocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	authority, _ := OpenStore(t.TempDir())
	authority.clock = func() time.Time { return now }
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	authority.signingKey = priv
	source := mustRegister(t, authority, "00:11:22:33:44:55", "A")
	target := mustRegister(t, authority, "00:11:22:33:44:56", "B")
	if err := authority.SetRule(source.ID, target.ID, true); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	replica, _ := OpenStore(dir)
	replica.replica = true
	replica.clock = func() time.Time { return now }
	replica.federation = &FederationConfig{PublicKey: base64.StdEncoding.EncodeToString(pub)}
	signed, _ := authority.signedSnapshot()
	if err := replica.applyPolicy(signed, false); err != nil {
		t.Fatal(err)
	}
	reg := registration("00:11:22:33:44:55", "A")
	c, err := replica.Register(reg)
	if err != nil {
		t.Fatal(err)
	}
	local, peer := net.Pipe()
	defer peer.Close()
	tracked, err := replica.Track(local, source.ID, target.ID, runID(c.Token))
	if err != nil {
		t.Fatal(err)
	}
	defer tracked.Close()
	tampered := signed
	tampered.Payload = append([]byte(nil), signed.Payload...)
	tampered.Payload[len(tampered.Payload)/2] ^= 1
	if replica.applyPolicy(tampered, false) == nil {
		t.Fatal("tampered snapshot accepted")
	}
	now = now.Add(time.Hour)
	authority.SetRule(source.ID, target.ID, false)
	revoked, _ := authority.signedSnapshot()
	if err := replica.applyPolicy(revoked, false); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("revocation did not close stream")
	}
	if replica.applyPolicy(signed, false) == nil {
		t.Fatal("rollback accepted")
	}
	authority.SetRule(source.ID, target.ID, true)
	fresh, _ := authority.signedSnapshot()
	replica.applyPolicy(fresh, false)
	cached, err := os.ReadFile(filepath.Join(dir, "policy-cache.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope signedPolicy
	json.Unmarshal(cached, &envelope)
	now = now.Add(24 * time.Hour)
	restarted, _ := OpenStore(dir)
	restarted.replica = true
	restarted.clock = func() time.Time { return now }
	restarted.federation = replica.federation
	if err := restarted.applyPolicy(envelope, true); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Register(reg); err != ErrDenied {
		t.Fatalf("restart extended expired lease: %v", err)
	}
	if restarted.applyPolicy(envelope, false) == nil {
		t.Fatal("expired snapshot accepted live")
	}
}
