package aissh

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SSHServiceStatus describes the target's system SSH endpoint, not tunnel health.
type SSHServiceStatus struct {
	State     string    `json:"state"`
	Detail    string    `json:"detail,omitempty"`
	CheckedAt time.Time `json:"checkedAt"`
}

func probeSSHService(port int) SSHServiceStatus {
	s := SSHServiceStatus{State: "stopped", CheckedAt: time.Now().UTC()}
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 750*time.Millisecond)
	if err != nil {
		s.Detail = "本机 SSH 服务未启动"
		if !sshServerInstalled() {
			s.State = "missing"
			s.Detail = "未安装 OpenSSH Server"
		}
		return s
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
	r := bufio.NewReaderSize(c, 8192)
	for i := 0; i < 8; i++ {
		line, e := r.ReadSlice('\n')
		if e == nil && (strings.HasPrefix(string(line), "SSH-2.0-") || strings.HasPrefix(string(line), "SSH-1.99-")) {
			s.State = "ready"
			s.Detail = "本机 SSH 服务已就绪"
			return s
		}
		if e != nil || len(line) > 8192 {
			break
		}
	}
	s.State = "unavailable"
	s.Detail = "端口可连接，但未返回 SSH 服务标识"
	return s
}

func sshRepairCommands(goos string, look func(string) (string, error)) ([][]string, error) {
	switch goos {
	case "windows":
		return [][]string{{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; $s=Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'; if($s.State -ne 'Installed'){Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null}; Set-Service -Name sshd -StartupType Automatic; Start-Service sshd`}}, nil
	case "darwin":
		return [][]string{{"/usr/sbin/systemsetup", "-setremotelogin", "on"}}, nil
	case "linux":
		commands := [][]string{}
		if _, err := look("sshd"); err != nil {
			switch {
			case available(look, "apt-get"):
				commands = append(commands, []string{"apt-get", "update"}, []string{"apt-get", "install", "-y", "openssh-server"})
			case available(look, "dnf"):
				commands = append(commands, []string{"dnf", "install", "-y", "openssh-server"})
			case available(look, "yum"):
				commands = append(commands, []string{"yum", "install", "-y", "openssh-server"})
			case available(look, "zypper"):
				commands = append(commands, []string{"zypper", "--non-interactive", "install", "openssh"})
			case available(look, "apk"):
				commands = append(commands, []string{"apk", "add", "openssh"})
			default:
				return nil, fmt.Errorf("不支持此 Linux 软件包管理器，请安装 OpenSSH Server")
			}
		}
		if available(look, "systemctl") {
			commands = append(commands, []string{"sh", "-c", `systemctl enable --now ssh.service || systemctl enable --now sshd.service`})
		} else if available(look, "rc-service") {
			commands = append(commands, []string{"ssh-keygen", "-A"}, []string{"rc-update", "add", "sshd", "default"}, []string{"rc-service", "sshd", "start"})
		} else {
			return nil, fmt.Errorf("未找到 systemd 或 OpenRC，请手动启用 SSH 服务")
		}
		return commands, nil
	}
	return nil, fmt.Errorf("此系统不支持自动配置 SSH")
}
func available(look func(string) (string, error), name string) bool {
	_, e := look(name)
	return e == nil
}

// PrepareSSHService runs only on explicit interactive launches, before the agent
// drops privileges. Background clients never prompt or invoke package managers.
func PrepareSSHService(port int) {
	s := probeSSHService(port)
	if s.State == "ready" && (!startupAdmin() || port != 22 || runtime.GOOS == "darwin") {
		log.Print("SSH 服务已就绪")
		return
	}
	if port != 22 {
		log.Printf("SSH：%s；自定义端口 %d 请手动配置", s.Detail, port)
		return
	}
	if !startupAdmin() {
		exe, _ := os.Executable()
		if runtime.GOOS == "windows" {
			log.Print("SSH 服务尚未就绪。请以管理员身份打开 PowerShell，再运行 .\\aisshc.exe --setup-ssh")
		} else {
			log.Printf("SSH 服务尚未就绪。请在终端执行：sudo '%s' --setup-ssh", strings.ReplaceAll(exe, "'", "'\"'\"'"))
		}
		return
	}
	cmds, err := sshRepairCommands(runtime.GOOS, exec.LookPath)
	if err != nil {
		log.Print(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	log.Print("正在安装或开启系统 SSH 服务，可能需要几分钟…")
	for _, args := range cmds {
		c := exec.CommandContext(ctx, args[0], args[1:]...)
		c.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
		out, e := c.CombinedOutput()
		if e != nil {
			log.Printf("SSH 自动配置失败：%v；%s", e, strings.TrimSpace(string(out)))
			if runtime.GOOS == "darwin" {
				log.Print("请在系统设置 → 隐私与安全性 → 完全磁盘访问中允许当前终端，或在 通用 → 共享 → 远程登录 手动开启并允许登录用户")
			}
			return
		}
	}
	s = probeSSHService(port)
	log.Printf("SSH 服务状态：%s（%s）", s.State, s.Detail)
}

func sshServerInstalled() bool {
	if runtime.GOOS == "darwin" {
		return true
	}
	if runtime.GOOS == "windows" {
		_, err := os.Stat(filepath.Join(os.Getenv("WINDIR"), "System32", "OpenSSH", "sshd.exe"))
		return err == nil
	}
	if available(exec.LookPath, "sshd") {
		return true
	}
	for _, p := range []string{"/usr/sbin/sshd", "/sbin/sshd", "/usr/local/sbin/sshd"} {
		if _, e := os.Stat(p); e == nil {
			return true
		}
	}
	return false
}

func (s *Store) recordSSHStatus(id, token string, status SSHServiceStatus) {
	switch status.State {
	case "ready", "missing", "stopped", "unavailable":
	default:
		return
	}
	if len(status.Detail) > 512 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.sessionLocked(id, token); err != nil {
		return
	}
	status.CheckedAt = s.now()
	s.state.Devices[id].SSHService = status
}
