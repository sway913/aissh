//go:build darwin

package aissh

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

const startupLabel = "com.builderopc.aisshc"
const startupPlistPath = "/Library/LaunchDaemons/com.builderopc.aisshc.plist"

type darwinStartup struct{ run startupCommand }

func newStartupBackend(run startupCommand) startupBackend { return &darwinStartup{run} }
func startupAdmin() bool                                  { return os.Geteuid() == 0 }
func (b *darwinStartup) status() (startupStatus, error) {
	if _, err := os.Stat(startupPlistPath); os.IsNotExist(err) {
		return startupStatus{}, nil
	} else if err != nil {
		return startupStatus{}, err
	}
	disabled, err := b.run("launchctl", "print-disabled", "system")
	if err != nil {
		return startupStatus{}, err
	}
	enabled := !strings.Contains(string(disabled), `"`+startupLabel+`" => true`)
	out, err := b.run("launchctl", "print", "system/"+startupLabel)
	if err != nil {
		if strings.Contains(string(out), "Could not find service") {
			return startupStatus{Installed: true, Enabled: enabled}, nil
		}
		return startupStatus{}, err
	}
	return startupStatus{true, strings.Contains(string(out), "state = running"), enabled}, nil
}
func plistString(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return "<string>" + b.String() + "</string>"
}
func darwinStartupPlist(c StartupConfig) string {
	dir, exe, _ := startupPaths("darwin")
	return `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>
<key>Label</key>` + plistString(startupLabel) + `
<key>UserName</key>` + plistString(c.User) + `
<key>ProgramArguments</key><array>` + plistString(exe) + plistString("--service-run") + `</array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer>
<key>StandardOutPath</key>` + plistString(dir+"/client.log") + `
<key>StandardErrorPath</key>` + plistString(dir+"/client.log") + `
</dict></plist>`
}
func (b *darwinStartup) install(c StartupConfig) error {
	// launchd opens these streams as the configured user, whose account cannot
	// create files in the root-owned installation directory.
	dir, _, _ := startupPaths("darwin")
	path := dir + "/client.log"
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing startup log symlink %s", path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	if err = f.Chown(c.UID, c.GID); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.WriteFile(startupPlistPath, []byte(darwinStartupPlist(c)), 0644)
}
func (b *darwinStartup) start() error {
	if _, err := b.run("launchctl", "enable", "system/"+startupLabel); err != nil {
		return err
	}
	out, err := b.run("launchctl", "print", "system/"+startupLabel)
	if err != nil {
		if !strings.Contains(string(out), "Could not find service") {
			return err
		}
		if _, err = b.run("launchctl", "bootstrap", "system", startupPlistPath); err != nil {
			return err
		}
	}
	_, err = b.run("launchctl", "kickstart", "system/"+startupLabel)
	return err
}
func (b *darwinStartup) stop() error {
	out, err := b.run("launchctl", "bootout", "system/"+startupLabel)
	if err != nil && !strings.Contains(string(out), "No such process") && !strings.Contains(string(out), "Could not find service") {
		return err
	}
	return nil
}
func (b *darwinStartup) remove() error {
	if err := os.Remove(startupPlistPath); err != nil {
		return fmt.Errorf("remove launch daemon: %w", err)
	}
	return nil
}

func protectStartupDirectory(dir string) error {
	if err := os.Chown(dir, 0, 0); err != nil {
		return err
	}
	return os.Chmod(dir, 0755)
}
