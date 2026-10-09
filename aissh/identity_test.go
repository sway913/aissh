package aissh

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

func identityAdapter(name, raw string) net.Interface {
	mac, _ := net.ParseMAC(raw)
	return net.Interface{Name: name, HardwareAddr: mac}
}

func TestFingerprintMACProviders(t *testing.T) {
	physical := identityAdapter("Ethernet", "00:11:22:33:44:55")
	for _, tc := range []struct {
		name         string
		adapters     []net.Interface
		enumErr      error
		wantFallback bool
	}{
		{name: "existing MAC preserved", adapters: []net.Interface{physical}},
		{name: "empty enumeration", wantFallback: true},
		{name: "enumeration error", enumErr: errors.New("adapter enumeration failed"), wantFallback: true},
		{name: "only unusable adapters", adapters: []net.Interface{identityAdapter("Loopback", "00:00:00:00:00:00"), identityAdapter("Docker0", "00:11:22:33:44:66")}, wantFallback: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			got, err := detectFingerprintMACs("windows", tc.adapters, tc.enumErr, func() ([]net.Interface, error) { called = true; return []net.Interface{physical}, nil })
			if err != nil || !reflect.DeepEqual(got, []string{"00:11:22:33:44:55"}) || called != tc.wantFallback {
				t.Fatalf("MAC=%v fallback=%v error=%v", got, called, err)
			}
		})
	}
	local := identityAdapter("Wi-Fi", "02:11:22:33:44:55")
	got := selectFingerprintMAC([]net.Interface{local, physical, identityAdapter("Ethernet2", "00:11:22:33:44:66")})
	if !reflect.DeepEqual(got, []string{"00:11:22:33:44:55"}) {
		t.Fatalf("primary MAC changed: %v", got)
	}
	if got = selectFingerprintMAC([]net.Interface{local}); !reflect.DeepEqual(got, []string{"02:11:22:33:44:55"}) {
		t.Fatalf("locally administered MAC lost: %v", got)
	}
}

func TestFingerprintWindowsAdapterJSON(t *testing.T) {
	adapters, err := parseWindowsAdapters([]byte("\ufeff" + `[{"Name":"以太网","MACAddress":"00-11-22-33-44-55"},{"Name":"Invalid","MACAddress":"invalid"},{"Name":"Zero","MACAddress":"00:00:00:00:00:00"}]`))
	if err != nil {
		t.Fatal(err)
	}
	got := selectFingerprintMAC(adapters)
	if !reflect.DeepEqual(got, []string{"00:11:22:33:44:55"}) {
		t.Fatal(got)
	}
	if _, err = parseWindowsAdapters([]byte("not JSON")); err == nil {
		t.Fatal("malformed adapter data accepted")
	}
}

func TestFingerprintNoMACDiagnostics(t *testing.T) {
	if _, err := detectFingerprintMACs("windows", nil, nil, func() ([]net.Interface, error) { return nil, nil }); err == nil || !strings.Contains(err.Error(), "no usable MAC") {
		t.Fatalf("%v", err)
	}
	failure := errors.New("CIM unavailable")
	if _, err := detectFingerprintMACs("windows", nil, nil, func() ([]net.Interface, error) { return nil, failure }); !errors.Is(err, failure) {
		t.Fatalf("%v", err)
	}
	if _, err := detectFingerprintMACs("linux", nil, failure, func() ([]net.Interface, error) { t.Fatal("Windows fallback on Linux"); return nil, nil }); !errors.Is(err, failure) {
		t.Fatalf("%v", err)
	}
}
