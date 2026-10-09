package aissh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Fingerprint is an identifier, not proof of possession. No private key is used.
type Fingerprint struct {
	MACs     []string `json:"macs"`
	Hardware []string `json:"hardware"`
}

func (f Fingerprint) ID() (string, error) {
	if len(f.MACs) == 0 || len(f.MACs) > 32 || len(f.Hardware) > 16 {
		return "", fmt.Errorf("invalid hardware fingerprint")
	}
	macs := make([]string, 0, len(f.MACs))
	for _, s := range f.MACs {
		m, err := net.ParseMAC(s)
		if err != nil || len(m) != 6 || m[0]&1 != 0 {
			return "", fmt.Errorf("invalid MAC")
		}
		macs = append(macs, m.String())
	}
	sort.Strings(macs)
	hardware := append([]string(nil), f.Hardware...)
	for _, s := range hardware {
		if len(s) != 64 {
			return "", fmt.Errorf("invalid hardware hash")
		}
		if _, err := hex.DecodeString(s); err != nil {
			return "", err
		}
	}
	sort.Strings(hardware)
	sum := sha256.Sum256([]byte("aissh-device-v1\nmac=" + strings.Join(macs, ",") + "\nhardware=" + strings.Join(hardware, ",")))
	return "dev-" + hex.EncodeToString(sum[:16]), nil
}

// selectFingerprintMAC retains the existing primary-MAC ordering across providers.
func selectFingerprintMAC(interfaces []net.Interface) []string {
	var global, local []string
	for _, i := range interfaces {
		n := strings.ToLower(i.Name)
		m := i.HardwareAddr
		if i.Flags&net.FlagLoopback != 0 || len(m) != 6 || m[0]&1 != 0 || m.String() == "00:00:00:00:00:00" {
			continue
		}
		if strings.HasPrefix(n, "docker") || strings.HasPrefix(n, "veth") || strings.HasPrefix(n, "br-") || strings.HasPrefix(n, "virbr") || strings.HasPrefix(n, "vmnet") || strings.HasPrefix(n, "utun") || strings.HasPrefix(n, "bridge") {
			continue
		}
		if m[0]&2 == 0 {
			global = append(global, m.String())
		} else {
			local = append(local, m.String())
		}
	}
	if len(global) == 0 {
		global = local
	}
	sort.Strings(global)
	if len(global) > 1 {
		global = global[:1]
	}
	return global
}

const windowsAdapterScript = `$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); ConvertTo-Json -Compress -InputObject @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.MACAddress } | Select-Object Name,MACAddress)`

func parseWindowsAdapters(data []byte) ([]net.Interface, error) {
	var adapters []struct {
		Name       string
		MACAddress string
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))), &adapters); err != nil {
		return nil, fmt.Errorf("decode Windows network adapters: %w", err)
	}
	var interfaces []net.Interface
	for _, a := range adapters {
		mac, err := net.ParseMAC(strings.TrimSpace(a.MACAddress))
		if err == nil {
			interfaces = append(interfaces, net.Interface{Name: a.Name, HardwareAddr: mac})
		}
	}
	return interfaces, nil
}

func windowsFingerprintMACs() ([]net.Interface, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	data, err := exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-Command", windowsAdapterScript).Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("Windows adapter query: %w", ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("Windows adapter query: %w", err)
	}
	return parseWindowsAdapters(data)
}

func detectFingerprintMACs(goos string, interfaces []net.Interface, enumErr error, fallback func() ([]net.Interface, error)) ([]string, error) {
	macs := selectFingerprintMAC(interfaces)
	if goos == "windows" && (enumErr != nil || len(macs) == 0) {
		adapters, err := fallback()
		if err != nil {
			return nil, fmt.Errorf("no usable MAC from network interfaces; %w", err)
		}
		macs = selectFingerprintMAC(adapters)
	} else if enumErr != nil {
		return nil, enumErr
	}
	if len(macs) == 0 {
		return nil, fmt.Errorf("no usable MAC address found; check that a network adapter is installed and enabled")
	}
	return macs, nil
}

func DetectFingerprint() (Fingerprint, error) {
	var f Fingerprint
	interfaces, enumErr := net.Interfaces()
	var err error
	f.MACs, err = detectFingerprintMACs(runtime.GOOS, interfaces, enumErr, windowsFingerprintMACs)
	if err != nil {
		return f, err
	}
	add := func(label, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			sum := sha256.Sum256([]byte(label + ":" + value))
			f.Hardware = append(f.Hardware, hex.EncodeToString(sum[:]))
		}
	}
	switch runtime.GOOS {
	case "linux":
		for _, p := range []string{"/sys/class/dmi/id/product_uuid", "/sys/class/dmi/id/board_serial", "/etc/machine-id"} {
			if b, e := os.ReadFile(p); e == nil {
				add(p, string(b))
			}
		}
	case "darwin":
		if b, e := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); e == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, "\"IOPlatformUUID\"") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						add("platform-uuid", strings.Trim(parts[1], " \""))
					}
				}
			}
		}
	case "windows":
		if b, e := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID").Output(); e == nil {
			add("platform-uuid", string(b))
		}
	}
	_, err = f.ID()
	return f, err
}
