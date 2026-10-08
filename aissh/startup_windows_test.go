//go:build windows

package aissh

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestWindowsScheduledTask(t *testing.T) {
	t.Setenv("ProgramData", `C:\ProgramData`)
	script := windowsTaskScript()
	for _, s := range []string{"-AtStartup", "'SYSTEM'", "ServiceAccount", "IgnoreNew", "RestartCount 999", "ExecutionTimeLimit", "--service-run"} {
		if !strings.Contains(script, s) {
			t.Fatalf("missing %q", s)
		}
	}
	if strings.Contains(script, "Password") || strings.Contains(script, "-Force") {
		t.Fatal("task stores password or overwrites registration")
	}
	if psQuote("a'b") != "'a''b'" {
		t.Fatal("PowerShell quote")
	}
	raw, _ := base64.StdEncoding.DecodeString(psEncoded("中文 & 'test'"))
	words := make([]uint16, len(raw)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	if string(utf16.Decode(words)) != "中文 & 'test'" {
		t.Fatal("Unicode command encoding")
	}
	b := newStartupBackend(func(string, ...string) ([]byte, error) {
		return []byte(`{"Installed":true,"Running":true,"Enabled":true}`), nil
	})
	s, err := b.status()
	if err != nil || s != (startupStatus{true, true, true}) {
		t.Fatalf("%+v %v", s, err)
	}
}
