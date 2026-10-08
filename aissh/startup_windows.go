//go:build windows

package aissh

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

type windowsStartup struct{ run startupCommand }

func newStartupBackend(run startupCommand) startupBackend { return &windowsStartup{run} }
func startupAdmin() bool                                  { return windows.GetCurrentProcessToken().IsElevated() }
func psQuote(s string) string                             { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func psEncoded(s string) string {
	words := utf16.Encode([]rune(s))
	raw := make([]byte, len(words)*2)
	for i, w := range words {
		binary.LittleEndian.PutUint16(raw[i*2:], w)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
func (b *windowsStartup) ps(s string) ([]byte, error) {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	return b.run(exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", psEncoded("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "+s))
}
func (b *windowsStartup) status() (startupStatus, error) {
	out, err := b.ps(`$t=Get-ScheduledTask -TaskName 'aisshc' -TaskPath '\' -ErrorAction SilentlyContinue; if($null -eq $t){'{}'}else{@{Installed=$true;Running=($t.State -eq 'Running');Enabled=($t.State -ne 'Disabled')}|ConvertTo-Json -Compress}`)
	if err != nil {
		return startupStatus{}, err
	}
	var s startupStatus
	err = json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(string(out), "\ufeff"))), &s)
	return s, err
}
func windowsTaskScript() string {
	dir, exe, _ := startupPaths("windows")
	return `$a=New-ScheduledTaskAction -Execute ` + psQuote(exe) + ` -Argument '--service-run' -WorkingDirectory ` + psQuote(dir) + `; $trigger=New-ScheduledTaskTrigger -AtStartup; $p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; $s=New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew; Register-ScheduledTask -TaskName 'aisshc' -TaskPath '\' -Action $a -Trigger $trigger -Principal $p -Settings $s | Out-Null`
}
func protectStartupDirectory(dir string) error {
	tool := filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe")
	// Reset prior explicit grants, transfer ownership, then remove inheritance.
	for _, args := range [][]string{
		{dir, "/reset", "/T"},
		{dir, "/setowner", "*S-1-5-32-544", "/T"},
		{dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/T"},
	} {
		if _, err := runStartupCommand(tool, args...); err != nil {
			return fmt.Errorf("protect startup directory: %w", err)
		}
	}
	return nil
}
func (b *windowsStartup) install(c StartupConfig) error {
	_, err := b.ps(windowsTaskScript())
	return err
}
func (b *windowsStartup) start() error {
	_, err := b.ps(`Enable-ScheduledTask -TaskName 'aisshc' -TaskPath '\' | Out-Null; Start-ScheduledTask -TaskName 'aisshc' -TaskPath '\'`)
	return err
}
func (b *windowsStartup) stop() error {
	_, err := b.ps(`Stop-ScheduledTask -TaskName 'aisshc' -TaskPath '\'; for($i=0;$i -lt 40;$i++){if((Get-ScheduledTask -TaskName 'aisshc' -TaskPath '\').State -ne 'Running'){exit 0};Start-Sleep -Milliseconds 250};throw 'task did not stop'`)
	return err
}
func (b *windowsStartup) remove() error {
	_, err := b.ps(`Unregister-ScheduledTask -TaskName 'aisshc' -TaskPath '\' -Confirm:$false`)
	return err
}
