package proc

import (
	"os/exec"
	"runtime"
)

func ShellCommand(command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("cmd", "/C", command)
	}
	return exec.Command("/bin/sh", "-lc", command)
}
