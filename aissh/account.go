package aissh

import (
	"os/user"
	"strings"
)

// sshUsername retains AD domains but removes the local computer prefix on Windows.
func sshUsername(goos, hostname, account string) string {
	account = strings.TrimSpace(account)
	if goos == "windows" {
		domain, name, ok := strings.Cut(account, `\`)
		if ok && (domain == "." || strings.EqualFold(domain, hostname)) {
			return name
		}
	}
	return account
}

func detectAccount(goos, hostname string) (username, account string, err error) {
	current, err := user.Current()
	if err != nil {
		return "", "", err
	}
	account = current.Username
	return sshUsername(goos, hostname, account), account, nil
}
