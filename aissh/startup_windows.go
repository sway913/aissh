//go:build windows

package aissh

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
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
	// Give directories inheritable ACEs, but files direct full-access ACEs.
	// Applying directory inheritance flags recursively with icacls can leave
	// existing files without an effective write grant during an update.
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing startup symlink %s", path)
		}
		sddl := "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
		if entry.IsDir() {
			sddl = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
		}
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return err
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			owner, nil, dacl, nil)
		if err != nil {
			return fmt.Errorf("protect startup path %s: %w", path, err)
		}
		return nil
	})
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
