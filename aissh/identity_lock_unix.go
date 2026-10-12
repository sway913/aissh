//go:build !windows

package aissh

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func lockAgentIdentity(dir string) (func(), error) {
	path := filepath.Join(dir, "identity.lock")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("aisshc already owns this identity; stop the background service before using --foreground: %w", err)
	}
	return func() { unix.Flock(fd, unix.LOCK_UN); unix.Close(fd) }, nil
}

func adoptIdentityUser(c *StartupConfig) error {
	if c == nil || os.Geteuid() != 0 || c.UID == 0 {
		return nil
	}
	u, err := user.LookupId(strconv.Itoa(c.UID))
	if err != nil {
		return err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return err
	}
	groups := make([]int, 0, len(ids))
	for _, id := range ids {
		n, e := strconv.Atoi(id)
		if e != nil {
			return e
		}
		groups = append(groups, n)
	}
	if err = syscall.Setgroups(groups); err != nil {
		return err
	}
	if err = syscall.Setgid(c.GID); err != nil {
		return err
	}
	if err = syscall.Setuid(c.UID); err != nil {
		return err
	}
	os.Setenv("HOME", u.HomeDir)
	return nil
}
