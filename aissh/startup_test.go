package aissh

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeStartup struct {
	state     startupStatus
	calls     []string
	statusErr error
	startErr  error
}

func (f *fakeStartup) status() (startupStatus, error) {
	f.calls = append(f.calls, "status")
	return f.state, f.statusErr
}
func (f *fakeStartup) install(StartupConfig) error {
	f.calls = append(f.calls, "install")
	f.state.Installed = true
	return nil
}
func (f *fakeStartup) start() error {
	f.calls = append(f.calls, "start")
	if f.startErr != nil {
		return f.startErr
	}
	f.state.Running = true
	f.state.Enabled = true
	return nil
}
func (f *fakeStartup) stop() error {
	f.calls = append(f.calls, "stop")
	f.state.Running = false
	return nil
}
func (f *fakeStartup) remove() error {
	f.calls = append(f.calls, "remove")
	f.state.Installed = false
	return nil
}
func TestStartupAlreadyRunning(t *testing.T) {
	f := &fakeStartup{state: startupStatus{true, true, true}}
	_, err := ensureStartup(f, AgentOptions{}, "", func() error { t.Fatal("running service asked for privileges"); return nil }, func(StartupConfig) error { t.Fatal("running service rewritten"); return nil })
	if err != nil || !reflect.DeepEqual(f.calls, []string{"status"}) {
		t.Fatalf("%v %v", f.calls, err)
	}
}
func TestStartupInstallationAndRepair(t *testing.T) {
	for _, installed := range []bool{false, true} {
		f := &fakeStartup{state: startupStatus{Installed: installed}}
		saves := 0
		admin := 0
		_, err := ensureStartup(f, AgentOptions{StateDir: t.TempDir(), APIURL: DefaultAPIURL, SSHPort: 22, TunnelPort: DefaultTunnelPort}, "", func() error { admin++; return nil }, func(StartupConfig) error { saves++; return nil })
		if err != nil {
			t.Fatal(err)
		}
		if !f.state.Running || !f.state.Enabled || admin != 1 {
			t.Fatalf("not repaired: %+v", f)
		}
		if installed && saves != 0 {
			t.Fatal("repair overwrote settings")
		}
		if !installed && (saves != 1 || !strings.Contains(strings.Join(f.calls, ","), "install,start")) {
			t.Fatal("missing initial install")
		}
	}
}
func TestStartupFailuresDoNotRunForeground(t *testing.T) {
	denied := errors.New("no permission")
	f := &fakeStartup{}
	_, err := ensureStartup(f, AgentOptions{}, "", func() error { return denied }, func(StartupConfig) error { t.Fatal("saved without privileges"); return nil })
	if !errors.Is(err, denied) || len(f.calls) != 1 {
		t.Fatalf("%v %v", f.calls, err)
	}
	f = &fakeStartup{statusErr: errors.New("scheduler inaccessible")}
	if _, err = ensureStartup(f, AgentOptions{}, "", func() error { return nil }, func(StartupConfig) error { return nil }); err == nil {
		t.Fatal("status failure treated as missing")
	}
	f = &fakeStartup{state: startupStatus{Installed: true}, startErr: errors.New("start failed")}
	if _, err = ensureStartup(f, AgentOptions{}, "", func() error { return nil }, func(StartupConfig) error { return nil }); err == nil {
		t.Fatal("failed start reported success")
	}
}
func TestStartupUninstall(t *testing.T) {
	f := &fakeStartup{state: startupStatus{true, true, true}}
	_, err := ensureStartup(f, AgentOptions{}, "uninstall", func() error { return nil }, func(StartupConfig) error { return nil })
	if err != nil || !reflect.DeepEqual(f.calls, []string{"status", "stop", "remove"}) {
		t.Fatalf("%v %v", f.calls, err)
	}
}
