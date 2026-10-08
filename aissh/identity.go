package aissh

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
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

func DetectFingerprint() (Fingerprint, error) {
	var f Fingerprint
	interfaces, err := net.Interfaces()
	if err != nil {
		return f, err
	}
	var local []string
	for _, i := range interfaces {
		n := strings.ToLower(i.Name)
		if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) != 6 || i.HardwareAddr[0]&1 != 0 {
			continue
		}
		if strings.HasPrefix(n, "docker") || strings.HasPrefix(n, "veth") || strings.HasPrefix(n, "br-") || strings.HasPrefix(n, "virbr") || strings.HasPrefix(n, "vmnet") || strings.HasPrefix(n, "utun") || strings.HasPrefix(n, "bridge") {
			continue
		}
		if i.HardwareAddr[0]&2 == 0 {
			f.MACs = append(f.MACs, i.HardwareAddr.String())
		} else {
			local = append(local, i.HardwareAddr.String())
		}
	}
	if len(f.MACs) == 0 {
		f.MACs = local
	}
	// Select one primary MAC deterministically; interface order/IP/DHCP changes do not affect the ID.
	sort.Strings(f.MACs)
	if len(f.MACs) > 1 {
		f.MACs = f.MACs[:1]
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
