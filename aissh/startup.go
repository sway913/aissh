package aissh

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// StartupConfig contains public device metadata and options, never session tokens.
type StartupConfig struct {
	Options  AgentOptions
	User     string
	UID      int
	GID      int
	Username string
	Account  string
	Hardware []string
}

type startupStatus struct{ Installed, Running, Enabled bool }
type startupBackend interface {
	status() (startupStatus, error)
	install(StartupConfig) error
	start() error
	stop() error
	remove() error
}

type startupCommand func(string, ...string) ([]byte, error)

func runStartupCommand(name string, args ...string) ([]byte, error) {
	c := exec.Command(name, args...)
	out, err := c.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, out)
	}
	return out, nil
}

func startupPaths(goos string) (dir, exe, config string) {
	switch goos {
	case "windows":
		dir = filepath.Join(os.Getenv("ProgramData"), "aissh")
	case "darwin":
		dir = "/Library/Application Support/aissh"
	default:
		dir = "/usr/local/lib/aissh"
	}
	exe = filepath.Join(dir, "aisshc")
	if goos == "windows" {
		exe += ".exe"
	}
	return dir, exe, filepath.Join(dir, "client.json")
}

func startupUser() (*user.User, error) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		return user.Lookup(os.Getenv("SUDO_USER"))
	}
	return user.Current()
}

func NewStartupConfig(o AgentOptions) (StartupConfig, error) {
	u, err := startupUser()
	if err != nil {
		return StartupConfig{}, err
	}
	if _, err := registrationURL(o.APIURL); err != nil {
		return StartupConfig{}, err
	}
	if o.SSHPort < 1 || o.SSHPort > 65535 || o.TunnelPort < 1 || o.TunnelPort > 65535 {
		return StartupConfig{}, fmt.Errorf("invalid SSH or tunnel port")
	}
	c := StartupConfig{Options: o, User: u.Username, Account: u.Username}
	name, _ := os.Hostname()
	c.Username = sshUsername(runtime.GOOS, name, u.Username)
	if runtime.GOOS != "windows" {
		c.UID, err = strconv.Atoi(u.Uid)
		if err != nil {
			return c, fmt.Errorf("invalid user UID: %w", err)
		}
		c.GID, err = strconv.Atoi(u.Gid)
		if err != nil {
			return c, fmt.Errorf("invalid user GID: %w", err)
		}
	}
	if runtime.GOOS == "windows" {
		fp, err := DetectFingerprint()
		if err != nil {
			return c, err
		}
		// SYSTEM must use the same hardware fields available to the installing user.
		// MAC addresses are still detected afresh every time the task starts.
		c.Hardware = fp.Hardware
		dir, _, _ := startupPaths(runtime.GOOS)
		c.Options.StateDir = filepath.Join(dir, "state")
	} else if os.Getenv("SUDO_USER") != "" {
		defaultHome, err := os.UserConfigDir()
		if err == nil && o.StateDir == filepath.Join(defaultHome, "aissh") {
			if runtime.GOOS == "darwin" {
				c.Options.StateDir = filepath.Join(u.HomeDir, "Library", "Application Support", "aissh")
			} else {
				c.Options.StateDir = filepath.Join(u.HomeDir, ".config", "aissh")
			}
		}
	}
	if o.CAFile != "" {
		c.Options.CAFile, err = filepath.Abs(o.CAFile)
		if err != nil {
			return c, err
		}
	}
	c.Options.StateDir, err = filepath.Abs(c.Options.StateDir)
	return c, err
}

func requireStartupAdmin() error {
	if !startupAdmin() {
		return fmt.Errorf("installing or repairing boot startup requires administrator privileges: Windows: run PowerShell as administrator; Linux/macOS: sudo ./aisshc (use --foreground to run without installation)")
	}
	return nil
}

func saveStartupFiles(c StartupConfig) error {
	dir, exe, config := startupPaths(runtime.GOOS)
	for _, path := range []string{dir, exe, exe + ".new", config, filepath.Join(dir, "tunnel-ca.pem")} {
		if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing startup symlink %s", path)
		} else if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := protectStartupDirectory(dir); err != nil {
		return err
	}
	src, err := os.Executable()
	if err != nil {
		return err
	}
	src, err = filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}
	if src != exe {
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(exe+".new", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		closeErr := out.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err = os.Rename(exe+".new", exe); err != nil {
			return err
		}
	}
	if c.Options.CAFile != "" {
		ca, err := os.ReadFile(c.Options.CAFile)
		if err != nil {
			return err
		}
		c.Options.CAFile = filepath.Join(dir, "tunnel-ca.pem")
		if err = os.WriteFile(c.Options.CAFile, ca, 0644); err != nil {
			return err
		}
	}
	if err = os.MkdirAll(c.Options.StateDir, 0700); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err = os.Chown(c.Options.StateDir, c.UID, c.GID); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(config, b, 0644)
}

// EnsureStartup never starts a second foreground agent. Existing registrations
// retain their original configuration unless explicitly updated.
func EnsureStartup(o AgentOptions, action string) (string, error) {
	b := newStartupBackend(runStartupCommand)
	return ensureStartup(b, o, action, requireStartupAdmin, saveStartupFiles)
}
func ensureStartup(b startupBackend, o AgentOptions, action string, admin func() error, save func(StartupConfig) error) (string, error) {
	s, err := b.status()
	if err != nil {
		return "", err
	}
	if action == "status" {
		return fmt.Sprintf("aisshc startup: installed=%t enabled=%t running=%t", s.Installed, s.Enabled, s.Running), nil
	}
	if action != "" && action != "update" && action != "uninstall" {
		return "", fmt.Errorf("unknown service action %q", action)
	}
	if action == "uninstall" {
		if !s.Installed {
			return "aisshc startup is not installed", nil
		}
		if err = admin(); err != nil {
			return "", err
		}
		if err = b.stop(); err != nil {
			return "", err
		}
		if err = b.remove(); err != nil {
			return "", err
		}
		return "aisshc startup removed; installed files and device permissions retained", nil
	}
	if s.Installed && s.Enabled && s.Running && action != "update" {
		return "aisshc startup already registered and running; no duplicate client started", nil
	}
	if err = admin(); err != nil {
		return "", err
	}
	if !s.Installed || action == "update" {
		c, err := NewStartupConfig(o)
		if err != nil {
			return "", err
		}
		if s.Installed {
			// Keep the registered execution identity and state directory on upgrades.
			old, loadErr := LoadStartupConfig()
			if loadErr != nil {
				return "", loadErr
			}
			c.User, c.UID, c.GID = old.User, old.UID, old.GID
			c.Username, c.Account, c.Hardware = old.Username, old.Account, old.Hardware
			c.Options.StateDir = old.Options.StateDir
			if err = b.stop(); err != nil {
				return "", err
			}
		}
		if err = save(c); err != nil {
			return "", err
		}
		if !s.Installed {
			if err = b.install(c); err != nil {
				return "", err
			}
		}
	}
	if err = b.start(); err != nil {
		return "", err
	}
	for i := 0; i < 20; i++ {
		s, err = b.status()
		if err != nil {
			return "", err
		}
		if s.Installed && s.Enabled && s.Running {
			return "aisshc boot startup registered and running; the background service now owns the client", nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return "", errors.New("startup registered but client did not remain running; inspect service/task logs")
}

func LoadStartupConfig() (StartupConfig, error) {
	_, _, path := startupPaths(runtime.GOOS)
	var c StartupConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}
