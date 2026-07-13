//go:build windows

package proc

import (
	"os"
	"time"
)

func IsRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	return err == nil && p != nil
}

func StopGroup(pid int, _ time.Duration) error {
	if pid <= 0 {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	return p.Kill()
}
