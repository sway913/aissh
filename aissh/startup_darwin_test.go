//go:build darwin

package aissh

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

func TestDarwinLaunchDaemon(t *testing.T) {
	plist := darwinStartupPlist(StartupConfig{User: "alice&bob"})
	dec := xml.NewDecoder(strings.NewReader(plist))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{"<key>UserName</key><string>alice&amp;bob</string>", "<key>RunAtLoad</key><true/>", "<key>KeepAlive</key><true/>", "--service-run", "/Library/Application Support/aissh/aisshc"} {
		if !strings.Contains(plist, s) {
			t.Fatalf("missing %q", s)
		}
	}
}
